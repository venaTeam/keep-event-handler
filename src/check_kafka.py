import confluent_kafka
from confluent_kafka import Consumer, KafkaException
import json
import os

def check_kafka():
    bootstrap_servers = "localhost:29092"
    topic = "keep-events"
    group_id = "keep-event-handler"
    
    conf = {
        "bootstrap.servers": bootstrap_servers,
        "group.id": group_id,
        "auto.offset.reset": "earliest",
    }
    
    try:
        consumer = Consumer(conf)
        metadata = consumer.list_topics(topic, timeout=10)
        if topic not in metadata.topics:
            print(f"Topic {topic} NOT found")
        else:
            partitions = metadata.topics[topic].partitions
            print(f"Topic {topic} found with {len(partitions)} partitions")
            
            for p in partitions:
                tp = confluent_kafka.TopicPartition(topic, p)
                low, high = consumer.get_watermark_offsets(tp, timeout=10)
                print(f"Partition {p}: Low offset: {low}, High offset: {high}, Total messages approximation: {high - low}")
                
                # Check committed offset for the group
                committed = consumer.committed([tp], timeout=10)
                if committed:
                    print(f"Group {group_id} committed offset for Partition {p}: {committed[0].offset}")
                else:
                    print(f"Group {group_id} has NO committed offset for Partition {p}")
            
        consumer.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_kafka()
