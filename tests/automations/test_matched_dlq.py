import json
from types import SimpleNamespace

import pytest
from confluent_kafka import KafkaError

from src.bl.automations import producer as module, settings
from src.bl.automations.producer import MatchedProducer, MatchedPublishError
from src.bl.automations.models import AutomationMatch
from src.bl.automations import publish_matches as orchestration
from src.bl.automations.rejection import rejection_payload


class Client:
    def __init__(self, errors=()):
        self.errors = list(errors)
        self.sent = []
        self.callbacks = []

    def produce(self, topic, **kwargs):
        self.sent.append((topic, kwargs))
        self.callbacks.append(kwargs['on_delivery'])

    def poll(self, timeout):
        if self.callbacks:
            self.callbacks.pop(0)(self.errors.pop(0) if self.errors else None, None)

    def list_topics(self, timeout):
        return SimpleNamespace(topics={name: SimpleNamespace(error=None)
                                      for name in (module.MATCHED_ALERTS_TOPIC, 'matched-alerts-dlq')})

    def flush(self, timeout):
        return len(self.callbacks)


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setattr(settings, 'AUTOMATION_MATCHING_ENABLED', True)
    monkeypatch.setattr(module, 'MAX_PROCESSING_RETRIES', 1)


def test_partial_delivery_falls_back_with_original_bytes_and_key():
    main, dlq = Client([None, RuntimeError()]), Client()
    producer = MatchedProducer(client=main, dlq_client=dlq)
    assert producer.publish([{'automation_id': 'a'}, {'automation_id': 'b'}]) == 'dlq'
    assert len(dlq.sent) == 1
    assert dlq.sent[0][1]['key'] == b'b'
    assert dlq.sent[0][1]['value'] == main.sent[1][1]['value']
    assert dict(dlq.sent[0][1]['headers'])['record-type'] == b'delivery'
    assert not producer.healthy
    assert producer.health()[0] is False  # metadata does not erase delivery failure
    assert producer.publish([{'automation_id': 'c'}]) == 'matched'
    assert producer.health()[0] is True


def test_both_fail_leave_unresolved():
    producer = MatchedProducer(client=Client([RuntimeError()]), dlq_client=Client([RuntimeError()]))
    with pytest.raises(MatchedPublishError, match='raw offset unresolved'):
        producer.publish([{'automation_id': 'a'}])
    assert producer.health_details()['last_result'] == 'unresolved'


def test_main_lock_contention_can_fall_back(monkeypatch):
    monkeypatch.setattr(settings, 'AUTOMATION_MATCHED_PUBLISH_TIMEOUT_SECONDS', 0.1)
    main, dlq = Client(), Client()
    producer = MatchedProducer(client=main, dlq_client=dlq)
    producer._healthy = True
    with producer._lock:
        assert producer.publish([{'automation_id': 'a'}]) == 'dlq'
    assert not main.sent
    assert producer.healthy


def test_permanent_error_does_not_retry(monkeypatch):
    monkeypatch.setattr(module, 'MAX_PROCESSING_RETRIES', 3)
    main, dlq = Client([KafkaError(KafkaError.MSG_SIZE_TOO_LARGE)]), Client()
    producer = MatchedProducer(client=main, dlq_client=dlq)
    assert producer.publish([{'automation_id': 'a'}]) == 'dlq'
    assert len(main.sent) == 1
    assert producer.health_details()['matched']['last_error']['code'] == KafkaError.MSG_SIZE_TOO_LARGE


def test_retry_does_not_resend_confirmed_sibling(monkeypatch):
    monkeypatch.setattr(module, 'MAX_PROCESSING_RETRIES', 2)
    main, dlq = Client([None, RuntimeError(), None]), Client()
    producer = MatchedProducer(client=main, dlq_client=dlq)
    producer.publish([{'automation_id': 'a'}, {'automation_id': 'b'}])
    assert [kwargs['key'] for _, kwargs in main.sent] == [b'a', b'b', b'b']
    assert not dlq.sent


def test_contract_rejection_stored_and_valid_sibling_continues(monkeypatch):
    main, dlq = Client(), Client()
    producer = MatchedProducer(client=main, dlq_client=dlq)
    monkeypatch.setattr(orchestration, 'get_matched_producer', lambda: producer)
    monkeypatch.setattr(orchestration, 'match', lambda *_: (AutomationMatch('a', 300, None),))
    orchestration.publish_matches('tenant', [{'id': None},
        {'id': 'ok', 'fingerprint': 'fp', 'time_created': 'now'}])
    assert len(main.sent) == len(dlq.sent) == 1
    envelope = json.loads(dlq.sent[0][1]['value'])
    assert envelope['kind'] == 'contract_rejection'
    assert envelope['automation_ids'] == ['a']
    assert envelope['replayable'] is False


def test_rejection_diagnostics_bounded_and_cycle_safe():
    data = {'huge': 'x' * 100000, 'bad': object(), 'nan': float('nan')}
    data['cycle'] = data
    raw = rejection_payload('tenant', data, (), ValueError('invalid'))
    assert len(raw) <= 65536
    assert json.loads(raw)['replayable'] is False


def test_unencodable_rejection_never_reaches_generic_terminal_handling(monkeypatch):
    from src.bl.automations import rejection
    monkeypatch.setattr(rejection, 'rejection_payload', lambda *_: (_ for _ in ()).throw(ValueError()))
    producer = MatchedProducer(client=Client(), dlq_client=Client())
    with pytest.raises(MatchedPublishError, match='raw offset unresolved'):
        producer.reject('tenant', {}, (), ValueError('invalid'))


def test_exhausted_raw_budget_never_commits_local_enqueue():
    main, dlq = Client(), Client()
    producer = MatchedProducer(client=main, dlq_client=dlq)
    token = module.delivery_budget.set(SimpleNamespace(remaining=lambda: 0))
    try:
        with pytest.raises(MatchedPublishError):
            producer.publish([{'automation_id': 'a'}])
    finally:
        module.delivery_budget.reset(token)
    assert not main.sent and not dlq.sent


def test_dlq_credentials_inherit_and_override(monkeypatch):
    monkeypatch.setenv('MATCHED_KAFKA_BOOTSTRAP_SERVERS', 'main:9092')
    monkeypatch.setenv('MATCHED_KAFKA_DLQ_BOOTSTRAP_SERVERS', 'fallback:9092')
    monkeypatch.setenv('MATCHED_KAFKA_SECURITY_PROTOCOL', 'SASL_SSL')
    monkeypatch.setenv('MATCHED_KAFKA_SASL_USERNAME', 'main-user')
    monkeypatch.setenv('MATCHED_KAFKA_DLQ_SASL_USERNAME', 'fallback-user')
    result = MatchedProducer._config(dlq=True)
    assert result['bootstrap.servers'] == 'fallback:9092'
    assert result['security.protocol'] == 'SASL_SSL'
    assert result['sasl.username'] == 'fallback-user'


@pytest.mark.parametrize('dlq_fails', [False, True])
@pytest.mark.parametrize('invalid_contract', [False, True])
def test_real_fallback_gates_raw_offset(monkeypatch, dlq_fails, invalid_contract):
    from unittest.mock import patch
    from tests.test_kafka_consumer_batch import _consumer_with_mock_kafka, _make_msg
    from src.core.kafka_consumer import RetryBudget
    main = Client([RuntimeError()])
    dlq = Client([RuntimeError()] if dlq_fails else [])
    producer = MatchedProducer(client=main, dlq_client=dlq)
    monkeypatch.setattr(orchestration, 'get_matched_producer', lambda: producer)
    monkeypatch.setattr(orchestration, 'match', lambda *_: (AutomationMatch('a', 300, None),))
    consumer, kafka = _consumer_with_mock_kafka()
    record = _make_msg('raw', 0, 0)
    payload = {} if invalid_contract else {'id': 'id', 'fingerprint': 'fp', 'time_created': 'now'}
    with patch('src.core.kafka_consumer.process_event_sync',
               side_effect=lambda dto: orchestration.publish_matches(dto.tenant_id, [payload])), \
            patch.object(consumer, '_record_terminal') as terminal:
        consumer._process_batch([record], RetryBudget(300000, max_sleep_seconds=0))
    terminal.assert_not_called()
    if dlq_fails:
        kafka.commit.assert_not_called()
    else:
        kafka.commit.assert_called_once_with(record, asynchronous=False)
        headers = dict(dlq.sent[0][1]['headers'])
        assert headers['source_offset'] == b'0'
