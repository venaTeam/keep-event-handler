from config.config import config
from config.consts import SecretManagerTypes, SECRET_MANAGER_TYPE
from contextmanager.contextmanager import ContextManager
from secretmanager.secretmanager import BaseSecretManager
from secretmanager.kubernetessecretmanager import KubernetesSecretManager

class SecretManagerFactory:
    @staticmethod
    def get_secret_manager(
        context_manager: ContextManager,
        secret_manager_type: SecretManagerTypes = None,
        **kwargs,
    ) -> BaseSecretManager:
        if not secret_manager_type:
            secret_manager_type = SECRET_MANAGER_TYPE
        elif secret_manager_type == SecretManagerTypes.K8S:

            return KubernetesSecretManager(context_manager, **kwargs)

        raise NotImplementedError(
            f"Secret manager type {str(secret_manager_type)} not implemented"
        )
