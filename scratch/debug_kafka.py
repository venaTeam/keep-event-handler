import json
from confluent_kafka import Consumer

conf = {
    'bootstrap.servers': 'localhost:29092',
    'group.id': 'keep-debug-consumer',
    'auto.offset.reset': 'earliest'
}

consumer = Consumer(conf)
consumer.subscribe(['keep-events'])

print("Starting debug consumer...")
try:
    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            print(f"Error: {msg.error()}")
            continue
            
        payload = json.loads(msg.value().decode('utf-8'))
        print(f"Type: {payload.get('event_type')} | FP: {payload.get('fingerprint')} | Trace: {payload.get('trace_id')}")
        # print(f"Event: {payload.get('event')}")
except KeyboardInterrupt:
    pass
finally:
    consumer.close()
