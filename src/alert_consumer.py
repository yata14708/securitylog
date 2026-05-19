"""
Alert Consumer
==============
Lightweight consumer that reads from logs-alerts Kafka topic
and prints formatted alerts to stdout.
"""

import json
import os
import time
from datetime import datetime
from confluent_kafka import Consumer, KafkaError

SEVERITY_ICONS = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
    "Benign":   "⚪",
    "Unknown":  "❓",
}


def format_alert(data: dict) -> str:
    src_ip    = data.get("src_ip", "N/A")
    reason    = data.get("alert_reason", "UNKNOWN")
    events    = data.get("event_count", 0)
    syn_ratio = data.get("syn_flag_ratio", 0.0)
    source    = data.get("dataset_source", "?").upper()
    win_start = data.get("window_start", "")
    ports     = data.get("unique_dst_ports", 0)

    return (
        f"🚨 ALERT [{source}] {win_start[:19]}\n"
        f"   src_ip       : {src_ip}\n"
        f"   reason       : {reason}\n"
        f"   event_count  : {int(events):,}\n"
        f"   syn_ratio    : {float(syn_ratio):.3f}\n"
        f"   unique_ports : {ports}\n"
    )


def main():
    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    topic             = os.environ.get("ALERT_TOPIC", "logs-alerts")
    group_id          = os.environ.get("GROUP_ID",    "alert-display")

    conf = {
        "bootstrap.servers":  bootstrap_servers,
        "group.id":           group_id,
        "auto.offset.reset":  "earliest",
        "enable.auto.commit": True,
    }

    print(f"[AlertConsumer] Connecting to {bootstrap_servers}, topic={topic}")

    # Wait for Kafka
    consumer = None
    for attempt in range(30):
        try:
            consumer = Consumer(conf)
            consumer.subscribe([topic])
            print(f"[AlertConsumer] Subscribed to '{topic}'")
            break
        except Exception as e:
            print(f"[AlertConsumer] Not ready yet ({e}). Retrying in 5s…")
            time.sleep(5)

    if consumer is None:
        print("[AlertConsumer] Could not connect. Exiting.")
        return

    total = 0
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"[AlertConsumer] Kafka error: {msg.error()}")
                continue

            try:
                data = json.loads(msg.value().decode("utf-8"))
                print(format_alert(data))
                total += 1
                if total % 100 == 0:
                    print(f"[AlertConsumer] Total alerts consumed: {total:,}")
            except Exception as e:
                print(f"[AlertConsumer] Parse error: {e}")

    except KeyboardInterrupt:
        print(f"\n[AlertConsumer] Stopped. Total alerts: {total:,}")
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
