# Security Log Analytics Pipeline

Real-time big data pipeline that ingests network intrusion detection logs from three public datasets, normalises them into a unified schema, detects anomalies, and serves interactive dashboards.

## Architecture

```
CICIDS2017 CSVs ─┐
UNSW-NB15 CSVs  ─┼─► Log Producer ─► Kafka (3 topics) ─► Spark Job 1 (Normalizer)
CIC-DDoS2019    ─┘                                              │           │
                                                         MinIO Parquet   logs-normalized
                                                    (normalized-logs/)    topic
                                                                            │
                                                                    Spark Job 2 (Aggregator)
                                                                            │           │
                                                                    MinIO Parquet   logs-alerts
                                                                (aggregations/)      topic
                                                                            │           │
                                                                    Spark Job 3   Alert Consumer
                                                                  (Batch Reports)   (stdout)
                                                                            │
                                                                    MinIO /reports/
                                                                            │
                                                               Trino (SQL on Parquet)
                                                                            │
                                                               Apache Superset (Dashboards)
```

## Services & Ports

| Service          | Port  | URL                        | Credentials     |
|------------------|-------|----------------------------|-----------------|
| Kafka            | 9092  | `localhost:9092`           | —               |
| MinIO API        | 9000  | `http://localhost:9000`    | admin / password|
| MinIO Console    | 9001  | `http://localhost:9001`    | admin / password|
| Trino UI         | 8080  | `http://localhost:8080`    | —               |
| Superset         | 8088  | `http://localhost:8088`    | admin / admin   |

## Datasets

Place the downloaded datasets under `../Dataset/` (one level above `code/`):

```
Dataset/
├── CIC-IDS-2017/          ← .zip files are read on-the-fly
│   ├── Monday-WorkingHours.pcap_ISCX.csv.zip
│   └── ...
├── UNSW-NB15/
│   ├── UNSW-NB15_1.csv    ← data files (no header)
│   └── ...
└── CIC-DDoS2019/
    ├── 01-12/
    │   └── *.csv
    └── 03-11/
        └── *.csv
```

## Quick Start

```bash
# 1. From the docker/ directory, start the full stack
cd code/docker
docker compose -f docker-compose.yaml up --build -d

# 2. Check all services are healthy (~2 min)
docker compose ps

# 3. Watch producer logs
docker compose logs -f log-producer

# 4. Watch normalizer (Spark Job 1)
docker compose logs -f spark-normalizer

# 5. Watch alerts
docker compose logs -f alert-consumer
```

## Data Flow

1. **Producer** — reads CSV/zip files from all three datasets using pandas (chunked), maps each dataset's columns to a common set of fields, publishes to `raw-cicids`, `raw-unsw`, or `raw-cicdos` Kafka topic, keyed by `src_ip`.

2. **Normalizer (Job 1)** — 30-second Spark micro-batches; subscribes to all 3 raw topics; maps fields → unified schema; adds `attack_category` and `severity_level` via UDF; writes Parquet to `s3a://data/normalized-logs/` partitioned by `attack_category` + `partition_date`; forwards enriched rows to `logs-normalized`.

3. **Aggregator (Job 2)** — 5-minute tumbling windows per `src_ip` with 2-minute watermark; computes event counts, SYN flag ratio, unique port counts; flags alerts when `event_count > 500` or `syn_flag_ratio > 0.8`; writes all windows to `s3a://data/aggregations-5min/`; alert rows go to `logs-alerts`.

4. **Batch Reporter (Job 3)** — runs every 5 minutes; reads full MinIO history; generates attack distribution, hourly time-series, top-IP behavioral profiles, and benign baseline statistics under `s3a://data/reports/`.

5. **Alert Consumer** — lightweight Python process; reads `logs-alerts` topic; prints formatted alerts with source IP, reason, event count, and SYN ratio.

6. **Trino** — SQL engine pointing to MinIO Parquet files. Tables and views are created automatically by `trino-init`.

7. **Superset** — dashboards at `http://localhost:8088`. Connect to Trino via:
   ```
   trino://trino:8080/hive/security_logs
   ```

## Unified Schema

| Field             | Type      | Description                            |
|-------------------|-----------|----------------------------------------|
| `src_ip`          | STRING    | Source IP address                      |
| `dst_ip`          | STRING    | Destination IP address                 |
| `src_port`        | BIGINT    | Source port                            |
| `dst_port`        | BIGINT    | Destination port                       |
| `protocol`        | STRING    | Protocol (TCP/UDP/etc.)                |
| `flow_duration`   | DOUBLE    | Flow duration                          |
| `total_fwd_packets`| BIGINT   | Packets in forward direction           |
| `total_bwd_packets`| BIGINT   | Packets in backward direction          |
| `flow_bytes_s`    | DOUBLE    | Bytes per second                       |
| `flow_packets_s`  | DOUBLE    | Packets per second                     |
| `syn_flag_count`  | BIGINT    | SYN flag count                         |
| `label`           | STRING    | Original dataset label                 |
| `attack_category` | STRING    | Normalised category (DDoS, Web_Attack…)|
| `severity_level`  | STRING    | Critical / High / Medium / Low / Benign|
| `dataset_source`  | STRING    | `cicids` / `unsw` / `cicdos`           |
| `event_timestamp` | TIMESTAMP | Processing timestamp                   |
| `partition_date`  | STRING    | YYYY-MM-DD partition key               |

## Sample Trino Queries

```sql
-- Attack counts by category (last 24 h)
SELECT attack_category, severity_level, COUNT(*) AS cnt
FROM hive.security_logs.normalized_logs
WHERE partition_date >= CAST(current_date - INTERVAL '1' DAY AS VARCHAR)
GROUP BY 1, 2
ORDER BY cnt DESC;

-- Active alerts
SELECT * FROM hive.security_logs.active_alerts LIMIT 20;

-- Top attacking IPs
SELECT * FROM hive.security_logs.top_src_ips LIMIT 10;
```

## Cleanup

```bash
# Stop all services
docker compose -f docker/docker-compose.yaml down

# Remove all data volumes (WARNING: deletes stored Parquet)
docker compose -f docker/docker-compose.yaml down -v
```