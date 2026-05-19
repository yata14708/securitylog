# Initial Plan: Data Processing Pipeline

This document outlines the architecture for our log processing and analytics pipeline. The data storage layer uses S3-compatible storage.

## Architecture Diagram

```mermaid
flowchart TD
    A1[CICIDS2017 CSVs] --> P
    A2[UNSW-NB15 CSVs] --> P
    A3[CIC-DDoS2019 CSVs] --> P

    P[log-producer container\nreads CSVs, converts to JSON,\nkeys each message by src_ip]

    P -->|topic: raw-cicids| K
    P -->|topic: raw-unsw| K
    P -->|topic: raw-cicdos| K

    K[Kafka Cluster\nkafka-1, kafka-2, kafka-3\n36 partitions total\n3x replicated]

    K -->|reads all 3 raw topics| J1

    J1[Spark Job 1 — Normalize\nparse each dataset differently\nmap all 3 schemas → unified schema\nrun every 30 seconds micro-batch]

    J1 -->|permanent storage\nall normalized events\ncolumnar Parquet format\npartitioned by attack_category| S3_1

    J1 -->|clean events forwarded\nfor real-time processing\ntopic: logs-normalized| K2

    S3_1[S3-Compatible Storage\ns3://data/normalized-logs/\nParquet files]

    K2[Kafka\ntopic: logs-normalized\nunified schema\nall 3 datasets merged]

    K2 -->|reads clean unified stream| J2

    J2[Spark Job 2 — Aggregate\n5-minute windows per src_ip\nwatermark 2 min for late events\nthreshold rules applied]

    J2 -->|all aggregations\nfor trend analysis| S3_2

    J2 -->|only alert-triggering rows\nhigh severity events only| K3

    S3_2[S3-Compatible Storage\ns3://data/aggregations-5min/\nParquet files]

    S3_1 -->|batch reads full history| J3
    S3_2 -->|batch reads full history| J3

    J3[Spark Job 3 — Batch\nruns periodically\nattack distribution\nbehavioral profiles\nhourly time series\nbenign baseline stats]

    J3 -->|report Parquet files| REPORTS

    K3[Kafka\ntopic: logs-alerts\nalert rows only]

    REPORTS[S3-Compatible Storage\ns3://data/reports/\nregistered in Hive Metastore]
    S3_1 -->|registered as tables| HIVE
    S3_2 -->|registered as tables| HIVE
    REPORTS -->|registered as tables| HIVE

    HIVE[Hive Metastore\nmaps table names to S3 paths\nno data stored here\njust metadata]

    HIVE -->|SQL queries via\nSpark Thrift Server| SUPERSET

    SUPERSET[Apache Superset\ndashboard and charts\nattack distribution\ntraffic time series\nalert timeline\nbehavioral profiles]
```

## Storage Layer
All data is stored in S3-compatible object storage. This includes:
- **Normalized logs:** `s3://data/normalized-logs/` (partitioned by attack category)
- **Aggregations:** `s3://data/aggregations-5min/` (5-minute windows)
- **Reports:** `s3://data/reports/` (batch job outputs)

Hive Metastore is used to map table names to their corresponding S3 paths to allow for SQL querying via Spark Thrift Server.
