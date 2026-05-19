"""
Log Producer
============
Reads real CSV files from CICIDS2017, UNSW-NB15, and CIC-DDoS2019 datasets.
Publishes JSON messages to separate Kafka topics keyed by src_ip.

Environment Variables:
  KAFKA_BOOTSTRAP_SERVERS  default: localhost:9092
  DATA_DIR                 default: /app/data  (mounted dataset root)
  PRODUCER_DELAY_MS        default: 0  (ms to sleep between rows; 0 = max speed)
"""

import json
import os
import time
import zipfile
import io
import threading
from datetime import datetime

import pandas as pd
from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic

# ---------------------------------------------------------------------------
# Column mappings  (raw CSV header -> normalised field name sent in JSON)
# ---------------------------------------------------------------------------

# CICIDS2017 and CIC-DDoS2019 share the same CICFlowMeter format.
# Column names have leading spaces in the CSV; we strip them on read.
CICIDS_MAP = {
    "Source IP":             "src_ip",
    "Destination IP":        "dst_ip",
    "Source Port":           "src_port",
    "Destination Port":      "dst_port",
    "Protocol":              "protocol",
    "Flow Duration":         "flow_duration",
    "Total Fwd Packets":     "total_fwd_packets",
    "Total Backward Packets":"total_bwd_packets",
    "Flow Bytes/s":          "flow_bytes_s",
    "Flow Packets/s":        "flow_packets_s",
    "SYN Flag Count":        "syn_flag_count",
    "Label":                 "label",
}

# UNSW-NB15 data files have no header row.
UNSW_COLUMNS = [
    "srcip","sport","dstip","dsport","proto","state","dur",
    "sbytes","dbytes","sttl","dttl","sloss","dloss","service",
    "sload","dload","spkts","dpkts","swin","dwin","stcpb","dtcpb",
    "smeansz","dmeansz","trans_depth","res_bdy_len","sjit","djit",
    "stime","ltime","sintpkt","dintpkt","tcprtt","synack","ackdat",
    "is_sm_ips_ports","ct_state_ttl","ct_flw_http_mthd","is_ftp_login",
    "ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm",
    "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","attack_cat","label",
]
UNSW_MAP = {
    "srcip":    "src_ip",
    "dstip":    "dst_ip",
    "sport":    "src_port",
    "dsport":   "dst_port",
    "proto":    "protocol",
    "dur":      "flow_duration",
    "spkts":    "total_fwd_packets",
    "dpkts":    "total_bwd_packets",
    "sload":    "flow_bytes_s",
    "dload":    "flow_packets_s",
    "attack_cat": "label",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CHUNK_SIZE = 500


def safe(val):
    """Convert numpy/nan to a JSON-serialisable Python type."""
    if val is None:
        return None
    try:
        import math
        if math.isnan(float(val)) or math.isinf(float(val)):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(val, "item"):          # numpy scalar
        return val.item()
    return val


def delivery_report(err, msg):
    if err is not None:
        print(f"[KAFKA] Delivery failed: {err}")


def create_topics(bootstrap_servers, topics):
    client = AdminClient({"bootstrap.servers": bootstrap_servers})
    existing = client.list_topics(timeout=10).topics
    new_topics = [
        NewTopic(t, num_partitions=3, replication_factor=1)
        for t in topics if t not in existing
    ]
    if new_topics:
        fs = client.create_topics(new_topics)
        for t, f in fs.items():
            try:
                f.result()
                print(f"[KAFKA] Created topic '{t}'")
            except Exception as e:
                print(f"[KAFKA] Topic '{t}' already exists or error: {e}")


# ---------------------------------------------------------------------------
# Row iterators  (yield one dict per CSV row)
# ---------------------------------------------------------------------------

def iter_cicids_file(filepath):
    """Yield dicts for one CICIDS2017 / CIC-DDoS2019 file (zip or plain csv)."""
    def _read_handle(fh):
        for chunk in pd.read_csv(
            fh,
            chunksize=CHUNK_SIZE,
            low_memory=False,
            na_filter=False,
            dtype=str,
        ):
            # Strip leading/trailing spaces from column names
            chunk.columns = [c.strip() for c in chunk.columns]
            for _, row in chunk.iterrows():
                record = {}
                for csv_col, out_col in CICIDS_MAP.items():
                    record[out_col] = safe(row.get(csv_col))
                yield record

    if filepath.lower().endswith(".zip"):
        with zipfile.ZipFile(filepath, "r") as zf:
            csv_name = next(
                n for n in zf.namelist() if n.lower().endswith(".csv")
            )
            with zf.open(csv_name) as raw:
                yield from _read_handle(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
    else:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            yield from _read_handle(fh)


def iter_unsw_file(filepath):
    """Yield dicts for one UNSW-NB15 file (no header row)."""
    # Detect whether this file has a header by peeking at the first line
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        first = f.readline().strip().lower()

    has_header = first.startswith("srcip") or first.startswith('"srcip')

    for chunk in pd.read_csv(
        filepath,
        chunksize=CHUNK_SIZE,
        low_memory=False,
        na_filter=False,
        dtype=str,
        header=0 if has_header else None,
        names=None if has_header else UNSW_COLUMNS,
    ):
        chunk.columns = [c.strip().lower() for c in chunk.columns]
        for _, row in chunk.iterrows():
            record = {}
            for csv_col, out_col in UNSW_MAP.items():
                record[out_col] = safe(row.get(csv_col))
            # UNSW binary label: 0=normal,1=attack. Prefer attack_cat as label.
            if not record.get("label"):
                record["label"] = safe(row.get("label", ""))
            yield record


# ---------------------------------------------------------------------------
# Producer thread  (one per dataset)
# ---------------------------------------------------------------------------

def producer_thread(bootstrap_servers, topic, dataset_source, file_list,
                    row_iterator_fn, delay_s, stop_event):
    conf = {
        "bootstrap.servers": bootstrap_servers,
        "client.id":          f"producer-{dataset_source}",
        "queue.buffering.max.messages": 500_000,
        "linger.ms":          50,
        "batch.size":         65_536,
        "compression.type":   "lz4",
    }
    producer = Producer(conf)
    sent = 0
    now_ts = lambda: int(datetime.now().timestamp() * 1000)

    while not stop_event.is_set():
        for fpath in file_list:
            if stop_event.is_set():
                break
            fname = os.path.basename(fpath)
            print(f"[{dataset_source.upper()}] Reading: {fname}")
            try:
                for record in row_iterator_fn(fpath):
                    if stop_event.is_set():
                        break

                    record["dataset_source"] = dataset_source
                    record["produced_at_ts"] = now_ts()

                    # Kafka message key = src_ip (fallback to "unknown")
                    key = str(record.get("src_ip") or "unknown").encode()
                    value = json.dumps(record, default=str).encode()

                    producer.produce(topic, key=key, value=value,
                                     callback=delivery_report)
                    sent += 1

                    if sent % 1000 == 0:
                        producer.poll(0)
                    if sent % 10_000 == 0:
                        print(f"[{dataset_source.upper()}] Sent {sent:,} rows → {topic}")

                    if delay_s > 0:
                        time.sleep(delay_s)

            except Exception as exc:
                print(f"[{dataset_source.upper()}] Error reading {fname}: {exc}")

        print(f"[{dataset_source.upper()}] Finished all files. Cycling again...")

    producer.flush()
    print(f"[{dataset_source.upper()}] Stopped. Total sent: {sent:,}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    data_dir          = os.environ.get("DATA_DIR", "/app/data")
    delay_ms          = float(os.environ.get("PRODUCER_DELAY_MS", "0"))
    delay_s           = delay_ms / 1000.0

    topics = ["raw-cicids", "raw-unsw", "raw-cicdos"]
    print(f"[MAIN] Waiting for Kafka at {bootstrap_servers}…")
    for _ in range(30):
        try:
            create_topics(bootstrap_servers, topics)
            break
        except Exception as e:
            print(f"[MAIN] Kafka not ready yet: {e}. Retrying in 5 s…")
            time.sleep(5)

    # ---- Collect file lists ----
    cicids_dir  = os.path.join(data_dir, "CIC-IDS-2017")
    unsw_dir    = os.path.join(data_dir, "UNSW-NB15")
    cicdos_dirs = [
        os.path.join(data_dir, "CIC-DDoS2019", "01-12"),
        os.path.join(data_dir, "CIC-DDoS2019", "03-11"),
    ]

    def list_files(d, exts=(".csv", ".zip")):
        if not os.path.isdir(d):
            print(f"[WARN] Directory not found: {d}")
            return []
        return sorted([
            os.path.join(d, f) for f in os.listdir(d)
            if f.lower().endswith(exts)
        ])

    cicids_files  = list_files(cicids_dir, (".csv", ".zip"))
    unsw_files    = [f for f in list_files(unsw_dir, (".csv",))
                     if "UNSW-NB15_" in os.path.basename(f)]   # skip GT file
    cicdos_files  = []
    for d in cicdos_dirs:
        cicdos_files.extend(list_files(d, (".csv",)))

    print(f"[MAIN] CICIDS files : {len(cicids_files)}")
    print(f"[MAIN] UNSW files   : {len(unsw_files)}")
    print(f"[MAIN] CICDDoS files: {len(cicdos_files)}")

    stop_event = threading.Event()
    threads = []

    if cicids_files:
        t = threading.Thread(
            target=producer_thread,
            args=(bootstrap_servers, "raw-cicids", "cicids",
                  cicids_files, iter_cicids_file, delay_s, stop_event),
            daemon=True,
        )
        threads.append(t)

    if unsw_files:
        t = threading.Thread(
            target=producer_thread,
            args=(bootstrap_servers, "raw-unsw", "unsw",
                  unsw_files, iter_unsw_file, delay_s, stop_event),
            daemon=True,
        )
        threads.append(t)

    if cicdos_files:
        t = threading.Thread(
            target=producer_thread,
            args=(bootstrap_servers, "raw-cicdos", "cicdos",
                  cicdos_files, iter_cicids_file, delay_s, stop_event),
            daemon=True,
        )
        threads.append(t)

    if not threads:
        print("[MAIN] No dataset files found! Check DATA_DIR mount.")
        return

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("[MAIN] Shutting down…")
        stop_event.set()

    for t in threads:
        t.join()
    print("[MAIN] All threads stopped.")


if __name__ == "__main__":
    main()
