import copy
import json
import logging
import os
import re
import typing

from config.consts import KEEP_USE_PROVIDER_CACHE
from contextmanager.contextmanager import ContextManager
from functions import cyaml
from providers.providers_factory import ProvidersFactory

class Parser:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._loaded_providers_cache = {}
        self._use_loaded_provider_cache = KEEP_USE_PROVIDER_CACHE

    def _load_providers_config(
        self,
        tenant_id,
        context_manager: ContextManager,
        providers_file: str,
    ):
        self.logger.debug("Parsing providers")
        providers_file = (
            providers_file or os.environ.get("KEEP_PROVIDERS_FILE") or "providers.yaml"
        )
        if providers_file and os.path.exists(providers_file):
            self._parse_providers_from_file(context_manager, providers_file)

        self._parse_providers_from_env(context_manager)
        self._load_providers_from_db(context_manager, tenant_id)
        self.logger.debug("Providers parsed and loaded successfully")

    def _parse_providers_from_env(self, context_manager: ContextManager):
        """
        Parse providers from the KEEP_PROVIDERS environment variables.
            Either KEEP_PROVIDERS to load multiple providers or KEEP_PROVIDER_<provider_name> can be used.

        KEEP_PROVIDERS is a JSON string of the providers config.
            (e.g. {"slack-prod": {"authentication": {"webhook_url": "https://hooks.slack.com/services/..."}}})
        """
        providers_json = os.environ.get("KEEP_PROVIDERS")

        # check if env var is absolute or relative path to a providers json file
        if providers_json and re.compile(r"^(\/|\.\/|\.\.\/).*\.json$").match(
            providers_json
        ):
            with open(file=providers_json, mode="r", encoding="utf8") as file:
                providers_json = file.read()

        if providers_json:
            try:
                self.logger.debug(
                    "Parsing providers from KEEP_PROVIDERS environment variable"
                )
                providers_dict = json.loads(providers_json)
                self._inject_env_variables(providers_dict)
                context_manager.providers_context.update(providers_dict)
                self.logger.debug(
                    "Providers parsed successfully from KEEP_PROVIDERS environment variable"
                )
            except json.JSONDecodeError:
                self.logger.error(
                    "Error parsing providers from KEEP_PROVIDERS environment variable"
                )

        for env in os.environ.keys():
            if env.startswith("KEEP_PROVIDER_"):
                # KEEP_PROVIDER_SLACK_PROD
                provider_name = (
                    env.replace("KEEP_PROVIDER_", "").replace("_", "-").lower()
                )
                try:
                    self.logger.debug(f"Parsing provider {provider_name} from {env}")
                    # {'authentication': {'webhook_url': 'https://hooks.slack.com/services/...'}}
                    provider_config = json.loads(os.environ.get(env))
                    self._inject_env_variables(provider_config)
                    context_manager.providers_context[provider_name] = provider_config
                    self.logger.debug(
                        f"Provider {provider_name} parsed successfully from {env}"
                    )
                except json.JSONDecodeError:
                    self.logger.error(
                        f"Error parsing provider config from environment variable {env}"
                    )

    def _inject_env_variables(self, config):
        """
        Recursively inject environment variables into the config.
        """
        if isinstance(config, dict):
            for key, value in config.items():
                config[key] = self._inject_env_variables(value)
        elif isinstance(config, list):
            return [self._inject_env_variables(item) for item in config]
        elif (
            isinstance(config, str) and config.startswith("$(") and config.endswith(")")
        ):
            env_var = config[2:-1]
            env_var_val = os.environ.get(env_var)
            if not env_var_val:
                self.logger.warning(
                    f"Environment variable {env_var} not found while injecting into config"
                )
                return config
            return env_var_val
        return config


    def _parse_actions_from_file(
        self, context_manager: ContextManager, actions_file: str
    ):
        """load actions from file into context manager"""
        if actions_file and os.path.isfile(actions_file):
            with open(actions_file, "r") as file:
                try:
                    actions_content = cyaml.safe_load(file)
                except cyaml.YAMLError:
                    self.logger.exception(f"Error parsing actions file {actions_file}")
                    raise
                # create a hashmap -> action
                for action in actions_content.get("actions", []):
                    context_manager.actions_context.update(
                        {action.get("use") or action.get("name"): action}
                    )

    def _load_actions_from_file(
        self, actions_file: typing.Optional[str]
    ) -> typing.Mapping[str, dict]:
        """load actions from file and convert results into a set of unique actions by id"""
        actions_set = {}
        if actions_file and os.path.isfile(actions_file):
            # load actions from a file
            actions = []
            with open(actions_file, "r") as file:
                try:
                    actions = cyaml.safe_load(file)
                except cyaml.YAMLError:
                    self.logger.exception(f"Error parsing actions file {actions_file}")
                    raise
            # convert actions into dictionary of unique object by id
            for action in actions:
                action_id = action.get("id") or action.get("name")
                if action_id or action_id not in actions_set:
                    actions_set[action_id] = action
                else:
                    self.logger.exception(
                        f"action defined in {actions_file} should have id as unique field"
                    )
        else:
            self.logger.warning(
                f"No action located at {actions_file}, skip loading reusable actions"
            )
        return actions_set


    def _extract_provider_id(self, context_manager: ContextManager, provider_type: str):
        """
        Translate {{ <provider_id>.<config_id> }} to a provider id

        Args:
            provider_type (str): _description_

        Raises:
            ValueError: _description_

        Returns:
            _type_: _description_
        """
        # TODO FIX THIS SHIT
        provider_type = provider_type.split(".")
        if len(provider_type) != 2:
            raise ValueError(
                f"Provider config ({provider_type}) is not valid, should be in the format: {{{{ <provider_id>.<config_id> }}}})"
            )

        provider_id = provider_type[1].replace("}}", "").strip()
        return provider_id

    def _parse_provider_config(
        self,
        context_manager: ContextManager,
        provider_type: str,
        provider_config: str | dict | None,
    ) -> tuple:
        """
        Parse provider config.
            If the provider config is a dict, return it as is.
            If the provider config is None, return an empty dict.
            If the provider config is a string, extract the config from the providers context.
            * When provider config is either dict or None, provider config id is the same as the provider type.

        Args:
            provider_type (str): The provider type
            provider_config (str | dict | None): The provider config

        Raises:
            ValueError: When the provider config is a string and the provider config id is not found in the providers context.

        Returns:
            tuple: provider id and provider parsed config
        """
        # Support providers without config such as logfile or mock
        if isinstance(provider_config, dict):
            return provider_type, provider_config
        elif provider_config is None:
            return provider_type, {"authentication": {}}
        # extract config when using {{ <provider_id>.<config_id> }}
        elif isinstance(provider_config, str):
            config_id = self._extract_provider_id(context_manager, provider_config)
            provider_config = context_manager.providers_context.get(config_id)
            if not provider_config:
                self.logger.warning(
                    "Provider not found in configuration, did you configure it?",
                    extra={
                        "provider_id": config_id,
                        "provider_type": provider_type,
                        "provider_config": provider_config,
                        "tenant_id": context_manager.tenant_id,
                    },
                )
                provider_config = {"authentication": {}}
            return config_id, provider_config

class ParserUtils:
    @staticmethod
    def deep_merge(source: dict, dest: dict) -> dict:
        """Perform deep merge on two objects.

        Example:
            source = {"deep1": {"deep2": 1}}
            dest = {"deep1", {"deep2": 2, "deep3": 3}}
            returns -> {"deep1": {"deep2": 1, "deep3": 3}}

        Returns:
            dict: The new object contains merged results
        """
        # make sure not to modify dest object by creating new one
        out = copy.deepcopy(dest)
        ParserUtils._merge(source, out)
        return out

    @staticmethod
    def _merge(ob1: dict, ob2: dict) -> dict:
        """Merge two objects, in case of duplicate key in two objects, take value of the first source"""
        for key, value in ob1.items():
            # encounter dict, merge into one
            if isinstance(value, dict) and key in ob2:
                next_node = ob2.get(key)
                ParserUtils._merge(value, next_node)
            # encounter list, merge by index and concat two lists
            elif isinstance(value, list) and key in ob2:
                next_nodes = ob2.get(key, [])
                for i in range(max(len(value), len(next_nodes))):
                    next_node = next_nodes[i] if i < len(next_nodes) else {}
                    value_node = value[i] if i < len(value) else {}
                    ParserUtils._merge(value_node, next_node)
            else:
                ob2[key] = value
