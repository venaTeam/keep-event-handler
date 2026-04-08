import inspect
import json
import os
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Generator
from unittest.mock import Mock, patch

try:
    import mysql.connector
except ImportError:
    mysql = None

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
from dotenv import find_dotenv, load_dotenv
from sqlalchemy import event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine
import tempfile

# Ensure PROMETHEUS_MULTIPROC_DIR is set before any keep imports
if "PROMETHEUS_MULTIPROC_DIR" not in os.environ:
    os.environ["PROMETHEUS_MULTIPROC_DIR"] = tempfile.mkdtemp(prefix="prometheus_multiproc_")

# This import is required to create the tables
from core.dependencies import SINGLE_TENANT_UUID
from core.elastic import ElasticClient
from models.alert import AlertStatus
from models.db.alert import *
from models.db.maintenance_window import MaintenanceWindowRule
from models.db.provider import *
from models.db.rule import *
from models.db.tenant import *
from models.db.user import *
from event_management.process_event_task import process_event
from utils.enrichment_helpers import convert_db_alerts_to_dto_alerts
from contextmanager.contextmanager import ContextManager

original_request = requests.Session.request  # noqa
load_dotenv(find_dotenv())

# Register fixture plugins
pytest_plugins = ["tests.fixtures.client"]

@pytest.fixture(scope="session", autouse=True)
def mock_providers_factory():
    def side_effect(provider_type):
        from models.alert import AlertDto
        class MockSafeProvider:
            PROVIDER_CATEGORY = "mock"
            PROVIDER_COMING_SOON = False
            PROVIDER_SCOPES = []
            WEBHOOK_INSTALLATION_REQUIRED = False
            PROVIDER_TAGS = []
            
            def __init__(self, *args, **kwargs):
                pass
                
            @staticmethod
            def simulate_alert():
                return {"id": "test_id", "name": "test_mock", "status": "firing", "fingerprint": "test_fingerprint", "source": ["test_provider"]}
                
            @staticmethod
            def format_alert(event, **kwargs):
                if isinstance(event, AlertDto):
                    return event
                return AlertDto(
                    id=event.get("id", "test_id"),
                    name=event.get("name", "test_mock"),
                    status=event.get("status", "firing"),
                    lastReceived=event.get("lastReceived", "2023-10-26T12:00:00Z"),
                    environment="test",
                    isDuplicate=False,
                    duplicateReason=None,
                    service=event.get("service", "test_service"),
                    source=[provider_type],
                    message=event.get("message", ""),
                    description=event.get("description", ""),
                    severity=event.get("severity", "info"),
                    pushed=True,
                    event_id=event.get("event_id", "test_id"),
                    fingerprint=event.get("fingerprint", "test_fingerprint"),
                    url=event.get("url", ""),
                    **{k: v for k, v in event.items() if k not in ["id", "name", "status", "lastReceived", "service", "source", "message", "description", "severity", "fingerprint", "url"]}
                )
                
            @classmethod
            def has_health_report(cls):
                return False
        return MockSafeProvider
        
    with patch("event_management.process_event_task.ProvidersFactory.get_provider_class", side_effect=side_effect):
        yield

@pytest.fixture(scope="session", autouse=True)
def mock_elastic_connection():
    with patch("core.elastic.ElasticClient") as mock_elastic:
        mock_instance = MagicMock()
        mock_elastic.return_value = mock_instance
        mock_instance.index_alert.return_value = None
        yield


class SSEMock:
    """Legacy mock class - not actively used anymore after SSE migration"""
    def __init__(self):
        self.triggers = []

    def trigger(self, channel, event_name, data):
        self.triggers.append((channel, event_name, data))


class WorkflowManagerMock:
    def __init__(self):
        self.events = []

    def get_instance(self):
        return self

    def insert_incident(self, tenant_id, incident_dto, action):
        self.events.append((tenant_id, incident_dto, action))


class ElasticClientMock:
    def __init__(self):
        self.alerts = []
        self.tenant_id = None
        self.enabled = True

    def __call__(self, tenant_id):
        self.tenant_id = tenant_id
        return self

    def index_alerts(self, alerts):
        self.alerts.append((self.tenant_id, alerts))


@pytest.fixture
def context_manager():
    os.environ["STORAGE_MANAGER_DIRECTORY"] = "/tmp/storage-manager"
    return ContextManager(tenant_id=SINGLE_TENANT_UUID, workflow_id="1234")


@pytest.fixture(scope="session", autouse=True)
def setup_prometheus_multiproc_dir(tmp_path_factory):
    """
    Sets up the PROMETHEUS_MULTIPROC_DIR environment variable for the session.
    """
    return os.environ["PROMETHEUS_MULTIPROC_DIR"]



@pytest.fixture(scope="session")
def docker_services(
    docker_compose_command,
    docker_compose_file,
    docker_compose_project_name,
    docker_setup,
    docker_cleanup,
):
    """Start the MySQL service (or any other service from docker-compose.yml)."""

    # If we are running in Github Actions, we don't need to start the docker services
    # as they are already handled by the Github Actions
    if os.getenv("GITHUB_ACTIONS") == "true":
        print("Running in Github Actions, skipping docker services")
        yield
        return

    # For local development, you can avoid spinning up the mysql container every time:
    if os.getenv("SKIP_DOCKER"):
        yield
        return

    # Else, start the docker services
    try:
        from pytest_docker.plugin import get_docker_services
        stack = inspect.stack()
        # this is a hack to support more than one docker-compose file
        for frame in stack:
            # if its a db_session, then we need to use the mysql docker-compose file
            if frame.function == "db_session":
                docker_compose_file = docker_compose_file.replace(
                    "docker-compose.yml", "docker-compose-mysql.yml"
                )
                break
            # if its a elastic_client, then we need to use the elastic docker-compose file
            elif frame.function == "elastic_client":
                docker_compose_file = docker_compose_file.replace(
                    "docker-compose.yml", "docker-compose-elastic.yml"
                )
                break

        print(f"Using docker-compose file: {docker_compose_file}")
        with get_docker_services(
            docker_compose_command,
            docker_compose_file,
            docker_compose_project_name,
            docker_setup,
            docker_cleanup,
        ) as docker_service:
            print("Docker services started")
            yield docker_service

    except Exception as e:
        print(f"Docker services could not be started: {e}")
        # Optionally, provide a fallback or mock service here
        raise


def is_mysql_responsive(host, port, user, password, database):
    try:
        # Create a MySQL connection
        connection = mysql.connector.connect(
            host=host, port=port, user=user, password=password, database=database
        )

        # Check if the connection is established
        if connection.is_connected():
            return True

    except Exception:
        print("Mysql still not up")
        pass

    return False


@pytest.fixture(scope="session")
def mysql_container(docker_ip, docker_services):
    try:
        if os.getenv("SKIP_DOCKER") or os.getenv("GITHUB_ACTIONS") == "true":
            print("Running in Github Actions or SKIP_DOCKER is set, skipping mysql")
            yield "mysql+pymysql://root:keep@localhost:3306/keep"
            return
        docker_services.wait_until_responsive(
            timeout=60.0,
            pause=0.1,
            check=lambda: is_mysql_responsive(
                "127.0.0.1", 3306, "root", "keep", "keep"
            ),
        )
        # set this as environment variable
        yield "mysql+pymysql://root:keep@localhost:3306/keep"
    except Exception:
        print("Exception occurred while waiting for MySQL to be responsive")
    finally:
        print("Tearing down MySQL")


@pytest.fixture
def db_session(request, monkeypatch, tmp_path):
    # Create a database connection
    print("Creating db session")
    os.environ["DB_ECHO"] = "true"
    # Set up a temporary directory for secret manager
    os.environ["SECRET_MANAGER_DIRECTORY"] = str(tmp_path)
    if (
        request
        and hasattr(request, "param")
        and request.param
        and "db" in request.param
    ):
        db_type = request.param.get("db")
        db_connection_string = request.getfixturevalue(f"{db_type}_container")
        monkeypatch.setenv("DATABASE_CONNECTION_STRING", db_connection_string)
        mock_engine = create_engine(db_connection_string)
    # sqlite
    else:
        db_connection_string = "sqlite:///:memory:"
        mock_engine = create_engine(
            db_connection_string,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        # @tb: leaving this here if anybody else gets to problem with nested transactions
        # https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#serializable-isolation-savepoints-transactional-ddl
        @event.listens_for(mock_engine, "connect")
        def do_connect(dbapi_connection, connection_record):
            # disable pysqlite's emitting of the BEGIN statement entirely.
            # also stops it from emitting COMMIT before any DDL.
            dbapi_connection.isolation_level = None

        @event.listens_for(mock_engine, "begin")
        def do_begin(conn):
            # emit our own BEGIN
            try:
                conn.exec_driver_sql(text("BEGIN EXCLUSIVE"))
            except Exception:
                pass

    SQLModel.metadata.create_all(mock_engine)

    # Mock the environment variables so db.py will use it
    os.environ["DATABASE_CONNECTION_STRING"] = db_connection_string

    # Create a session
    # Passing class_=Session to use the Session class from sqlmodel (https://github.com/fastapi/sqlmodel/issues/75#issuecomment-2109911909)
    SessionLocal = sessionmaker(
        class_=Session, autocommit=False, autoflush=False, bind=mock_engine
    )
    session = SessionLocal()
    # Prepopulate the database with test data

    # 1. Create a tenant
    tenant_data = [
        Tenant(id=SINGLE_TENANT_UUID, name="test-tenant", created_by="tests@keephq.dev")
    ]
    session.add_all(tenant_data)
    session.commit()
    # Note: Workflow models don't exist in keep-event-handler, skipping workflow prepopulation

    with patch("core.db.db.engine", mock_engine):
        with patch("core.db.db_utils.create_db_engine", return_value=mock_engine):
            yield session

    import logging

    # Close any custom handlers to stop background threads before dropping tables
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        if handler.__class__.__name__ in ("WorkflowDBHandler", "FluentBitHandler"):
            handler.close()
            root_logger.removeHandler(handler)

    logger = logging.getLogger(__name__)
    logger.info("Dropping all tables")
    # delete the database
    SQLModel.metadata.drop_all(mock_engine)
    # Clean up after the test
    session.close()


@pytest.fixture
def mocked_context_manager():
    context_manager = Mock(spec=ContextManager)
    # Simulate contexts as needed for each test case
    context_manager.steps_context = {}
    context_manager.providers_context = {}
    context_manager.event_context = {}
    context_manager.click_context = {}
    context_manager.foreach_context = {"value": None}
    context_manager.dependencies = set()
    context_manager.get_full_context.return_value = {
        "steps": {},
        "providers": {},
        "event": {},
        "alert": {},
        "foreach": {"value": None},
        "env": {},
    }
    context_manager.tenant_id = SINGLE_TENANT_UUID
    return context_manager


def is_elastic_responsive(host, port, user, password):
    try:
        elastic_client = ElasticClient(
            tenant_id=SINGLE_TENANT_UUID,
            hosts=[f"http://{host}:{port}"],
            basic_auth=(user, password),
        )
        info = elastic_client._client.info()
        print("Elastic still up now")
        return True if info else False
    except Exception:
        print("Elastic still not up")
        pass

    return False


@pytest.fixture(scope="session")
def elastic_container(docker_ip, docker_services):
    try:
        if os.getenv("SKIP_DOCKER") or os.getenv("GITHUB_ACTIONS") == "true":
            print("Running in Github Actions or SKIP_DOCKER is set, skipping elastic")
            yield
            return
        docker_services.wait_until_responsive(
            timeout=60.0,
            pause=0.1,
            check=lambda: is_elastic_responsive(
                "127.0.0.1", 9200, "elastic", "keeptests"
            ),
        )
        yield True
    except Exception:
        print("Exception occurred while waiting for Elasticsearch to be responsive")
        raise
    finally:
        print("Tearing down Elasticsearch")


@pytest.fixture
def elastic_client(request):
    if hasattr(request, "param") and request.param is False:
        yield None
    else:
        # this is so if any other module initialized Elasticsearch, it will be deleted
        ElasticClient._instance = None
        env_vars = {}
        env_vars["ELASTIC_ENABLED"] = "true"
        env_vars["ELASTIC_USER"] = "elastic"
        env_vars["ELASTIC_PASSWORD"] = "keeptests"
        env_vars["ELASTIC_HOSTS"] = "http://localhost:9200"
        env_vars["ELASTIC_INDEX_SUFFIX"] = "test"

        with patch.dict(os.environ, env_vars):
            try:
                elastic_client_inst = ElasticClient(
                    tenant_id=SINGLE_TENANT_UUID,
                )
                
                # Check connection early to catch failures
                if not elastic_client_inst._client.ping():
                    raise Exception("ElasticSearch ping failed")

                yield elastic_client_inst

                # remove all from elasticsearch
                try:
                    elastic_client_inst.drop_index()
                except Exception:
                    pass
            except Exception as e:
                print(f"ElasticSearch unavailable: {e}")
                yield ElasticClientMock()


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    import os
    return os.path.join(
        str(pytestconfig.rootdir),
        "tests",
        "docker-compose-elastic.yml",
    )


def _create_valid_event(d, lastReceived=None):
    event = {
        "id": str(uuid.uuid4()),
        "name": "some-test-event",
        "status": "firing",
        "lastReceived": (
            str(lastReceived)
            if lastReceived
            else datetime.now(tz=timezone.utc).isoformat()
        ),
    }
    event.update(d)
    return event


@pytest.fixture
def setup_alerts(elastic_client, db_session, request):
    alert_details = request.param.get("alert_details")
    alerts = []
    for i, detail in enumerate(alert_details):
        # sleep to avoid same lastReceived
        time.sleep(0.02)
        detail["fingerprint"] = f"test-{i}"
        if "source" in detail:
            source = detail["source"][0]
        alerts.append(
            Alert(
                tenant_id=SINGLE_TENANT_UUID,
                provider_type=source,
                provider_id="test",
                event=_create_valid_event(detail),
                fingerprint=detail["fingerprint"],
            )
        )
    db_session.add_all(alerts)
    db_session.commit()

    existed_last_alerts = db_session.query(LastAlert).all()
    existed_last_alerts_dict = {
        last_alert.fingerprint: last_alert for last_alert in existed_last_alerts
    }

    last_alerts = []
    for alert in alerts:
        if alert.fingerprint in existed_last_alerts_dict:
            last_alert = existed_last_alerts_dict[alert.fingerprint]
            last_alert.alert_id = alert.id
            last_alert.timestamp = alert.timestamp
            last_alerts.append(last_alert)
        else:
            last_alerts.append(
                LastAlert(
                    tenant_id=SINGLE_TENANT_UUID,
                    fingerprint=alert.fingerprint,
                    timestamp=alert.timestamp,
                    first_timestamp=alert.timestamp,
                    alert_id=alert.id,
                )
            )
    db_session.add_all(last_alerts)
    db_session.commit()

    # add all to elasticsearch
    if elastic_client:
        alerts_dto = convert_db_alerts_to_dto_alerts(alerts)
        try:
            elastic_client.index_alerts(alerts_dto)
        except Exception as e:
            print(f"Skipping elastic indexing due to: {e}")


@pytest.fixture
def setup_stress_alerts_no_elastic(db_session):
    def _setup_stress_alerts_no_elastic(num_alerts):
        alert_details = [
            {
                "source": [
                    "source_{}".format(i % 10)
                ],  # Cycle through 10 different sources
                "service": "service_{}".format(
                    i % 10
                ),  # Random of 10 different services
                "severity": random.choice(
                    ["info", "warning", "critical"]
                ),  # Alternate between 'critical' and 'warning'
                "fingerprint": f"test-{i}",
            }
            for i in range(num_alerts)
        ]
        alerts = []
        for i, detail in enumerate(alert_details):
            random_timestamp = datetime.utcnow() - timedelta(days=random.uniform(0, 7))
            alerts.append(
                Alert(
                    timestamp=random_timestamp,
                    tenant_id=SINGLE_TENANT_UUID,
                    provider_type=detail["source"][0],
                    provider_id="test_{}".format(
                        i % 5
                    ),  # Cycle through 5 different provider_ids
                    event=_create_valid_event(detail, lastReceived=random_timestamp),
                    fingerprint="fingerprint_{}".format(i),
                )
            )
        db_session.add_all(alerts)
        db_session.commit()

        existed_last_alerts = db_session.query(LastAlert).all()
        existed_last_alerts_dict = {
            last_alert.fingerprint: last_alert for last_alert in existed_last_alerts
        }
        last_alerts = []
        for alert in alerts:
            if alert.fingerprint in existed_last_alerts_dict:
                last_alert = existed_last_alerts_dict[alert.fingerprint]
                last_alert.alert_id = alert.id
                last_alert.timestamp = alert.timestamp
                last_alerts.append(last_alert)
            else:
                last_alerts.append(
                    LastAlert(
                        tenant_id=SINGLE_TENANT_UUID,
                        fingerprint=alert.fingerprint,
                        timestamp=alert.timestamp,
                        first_timestamp=alert.timestamp,
                        alert_id=alert.id,
                    )
                )
        db_session.add_all(last_alerts)
        db_session.commit()

        return alerts

    return _setup_stress_alerts_no_elastic


@pytest.fixture
def setup_stress_alerts(
    elastic_client, db_session, request, setup_stress_alerts_no_elastic
):
    num_alerts = request.param.get(
        "num_alerts", 1000
    )  # Default to 1000 alerts if not specified
    alerts = setup_stress_alerts_no_elastic(num_alerts)
    # add all to elasticsearch
    alerts_dto = convert_db_alerts_to_dto_alerts(alerts)
    elastic_client.index_alerts(alerts_dto)


@pytest.fixture
def create_alert(db_session):
    def _create_alert(
        fingerprint, status, timestamp, details=None, tenant_id=SINGLE_TENANT_UUID
    ):
        details = details or {}
        if fingerprint and "fingerprint" not in details:
            details["fingerprint"] = fingerprint

        random_name = "test-{}".format(fingerprint)
        process_event(
            ctx={"job_try": 1},
            trace_id="test",
            tenant_id=tenant_id,
            provider_id="test",
            provider_type=(
                details["source"][0]
                if details and "source" in details and details["source"]
                else None
            ),
            fingerprint=fingerprint,
            api_key_name="test",
            event={
                "name": random_name,
                "lastReceived": details.pop("lastReceived", timestamp.isoformat()),
                "status": status.value,
                **details,
            },
            notify_client=False,
            timestamp_forced=timestamp,
        )

    return _create_alert


@pytest.fixture
def create_window_maintenance_active(db_session):
    def _create_window_maintenance_active(
        start: datetime,
        end: datetime,
        cel: str,
        tenant_id: str = SINGLE_TENANT_UUID,
        name: str = "Test Maintenance Window",
        description: str = "This is a test maintenance window",
    ):
        """Create a maintenance window in the database."""
        window = MaintenanceWindowRule(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=name,
            description=description,
            start_time=start,
            end_time=end,
            created_by="test_user",
            cel_query=cel,
            enabled=True,
            suppress=True,
            ignore_statuses=[
                AlertStatus.RESOLVED.value,
                AlertStatus.ACKNOWLEDGED.value,
            ],
        )
        db_session.add(window)
        db_session.commit()
        return window

    return _create_window_maintenance_active


@pytest.fixture
def finalize_window_maintenance(db_session):
    def _finalize_window_maintenance(rule_id, tenant_id: str = SINGLE_TENANT_UUID):
        rule: MaintenanceWindowRule = (
            db_session.query(MaintenanceWindowRule)
            .filter(
                MaintenanceWindowRule.tenant_id == tenant_id,
                MaintenanceWindowRule.id == rule_id,
            )
            .first()
        )
        rule.end_time = datetime.now(tz=timezone.utc) - timedelta(seconds=30)
        rule.enabled = False

        db_session.commit()
        db_session.refresh(rule)

    return _finalize_window_maintenance


def pytest_addoption(parser):
    """
    Adds configuration options for integration tests
    """

    parser.addoption(
        "--integration", action="store_const", const=True, dest="run_integration"
    )
    parser.addoption(
        "--non-integration",
        action="store_const",
        const=True,
        dest="run_non_integration",
    )


def pytest_configure(config):
    """
    Adds markers for integration tests
    """
    config.addinivalue_line(
        "markers", "integration: mark test to run only if integrations tests enabled"
    )


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """
    Checks whether tests should be skipped based on integration settings
    """

    run_integration = item.config.getoption("run_integration")
    run_non_integration = item.config.getoption("run_non_integration")

    if run_integration and run_non_integration is None:
        run_non_integration = False
    if run_non_integration and run_integration is None:
        run_integration = False

    if item.get_closest_marker("integration"):
        if run_integration in (None, True):
            return
        pytest.skip("Integration tests skipped")
    else:
        if run_non_integration in (None, True):
            return
        pytest.skip("Non-Integration tests skipped")


def pytest_collection_modifyitems(items):
    for item in items:
        fixturenames = getattr(item, "fixturenames", ())
        if "elastic_client" in fixturenames:
            item.add_marker("integration")
        elif (
            hasattr(item, "callspec")
            and "db_session" in item.callspec.params
            and item.callspec.params["db_session"]
            and "db" in item.callspec.params["db_session"]
        ):
            item.add_marker("integration")


@pytest.fixture
def console_logs():
    """Fixture to collect console logs during test execution."""
    logs = []
    return logs


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call) -> Generator[None, Any, Any]:
    """Hook to store test results for use in fixtures."""
    outcome = yield
    rep = outcome.get_result()

    # Set report for each phase (setup, call, teardown)
    setattr(item, f"rep_{rep.when}", rep)
