# Real-Time Security Log Analytics - Implementation Plan

**Project Goal**: Build a real-time big data pipeline for analyzing high-traffic security logs with anomaly detection and interactive visualization.

**Tech Stack**: Kafka, Spark Streaming, MinIO (S3), Trino, Apache Superset

---

## System Architecture

```mermaid
flowchart TB
    subgraph Ingestion["Data Ingestion Layer"]
        P[Log Producer<br/>Generates CICIDS2017<br/>security events]
    end
    
    subgraph Messaging["Message Queue"]
        K1[Kafka Topic<br/>raw-cicids]
        K2[Kafka Topic<br/>security-alerts]
    end
    
    subgraph Processing["Stream Processing Layer"]
        C[Spark Consumer<br/>Normalization & Classification<br/>- Parse JSON logs<br/>- Classify attack types<br/>- Calculate risk scores<br/>- Partition by category]
        A[Spark Aggregator<br/>Windowed Analytics<br/>- 5-min tumbling windows<br/>- Detect anomalies<br/>- Calculate metrics<br/>- Generate alerts]
    end
    
    subgraph Storage["Data Lake - MinIO S3"]
        S1[(Normalized Logs<br/>s3://data/normalized-logs/<br/>Partitioned by:<br/>attack_category, date)]
        S2[(Aggregations<br/>s3://data/aggregations-5min/<br/>Windowed metrics)]
    end
    
    subgraph Analytics["Query & Visualization"]
        T[Trino SQL Engine<br/>Ad-hoc queries on<br/>Parquet files]
        SU[Apache Superset<br/>Interactive Dashboards<br/>- Attack distribution<br/>- Time series<br/>- Top attackers]
    end
    
    P -->|JSON events| K1
    K1 -->|Reads| C
    K1 -->|Reads| A
    C -->|Writes Parquet| S1
    A -->|Writes Parquet| S2
    A -->|Anomalies only| K2
    S1 -->|Queries| T
    S2 -->|Queries| T
    T -->|SQL| SU
    
    style P fill:#e1f5ff
    style K1 fill:#fff4e1
    style K2 fill:#fff4e1
    style C fill:#e8f5e9
    style A fill:#e8f5e9
    style S1 fill:#f3e5f5
    style S2 fill:#f3e5f5
    style T fill:#fce4ec
    style SU fill:#fce4ec
```

---

## Data Flow

```mermaid
sequenceDiagram
    participant Producer
    participant Kafka
    participant Consumer
    participant Aggregator
    participant MinIO
    participant Trino
    participant Superset
    
    Producer->>Kafka: Publish security logs<br/>(topic: raw-cicids)
    
    par Parallel Processing
        Kafka->>Consumer: Stream logs
        Consumer->>Consumer: 1. Parse JSON<br/>2. Classify attack<br/>3. Calculate risk score
        Consumer->>MinIO: Write Parquet<br/>(partitioned by category)
    and
        Kafka->>Aggregator: Stream logs
        Aggregator->>Aggregator: 1. 5-min windows<br/>2. Calculate metrics<br/>3. Detect anomalies
        Aggregator->>MinIO: Write aggregations
        Aggregator->>Kafka: Publish alerts<br/>(topic: security-alerts)
    end
    
    Superset->>Trino: SQL query
    Trino->>MinIO: Read Parquet files
    MinIO-->>Trino: Return data
    Trino-->>Superset: Query results
    Superset->>Superset: Render dashboard
```

---

## Implementation Steps

### Phase 1: Enhanced Stream Processing (Day 1-2)

#### 1.1 Create Aggregator Job
**File**: `src/aggregator.py`

**Features**:
- 5-minute tumbling windows
- Group by: `destination_port` (or source IP proxy)
- Metrics: event_count, unique_labels, avg_flow_duration, syn_flag_ratio
- Anomaly detection: flag when event_count > 5000 OR syn_flag_ratio > 0.8
- Watermark: 2 minutes for late events

**Outputs**:
- `s3a://data/aggregations-5min/` (all windows)
- Kafka topic `security-alerts` (anomalies only)

#### 1.2 Enhance Consumer
**File**: `src/consumer.py`

**Additions**:
```python
# Add attack classification UDF
def classify_attack_category(label):
    if "DDoS" in label: return "DDoS"
    elif any(x in label for x in ["Brute Force", "XSS", "Sql Injection"]): return "Web_Attack"
    elif "PortScan" in label: return "Reconnaissance"
    elif "Patator" in label: return "Credential_Attack"
    elif "BENIGN" in label: return "Benign"
    else: return "Other"

# Add columns
.withColumn("attack_category", classify_attack_category_udf(col("label")))
.withColumn("severity_level", calculate_severity_udf(col("attack_category")))
.withColumn("risk_score", calculate_risk_udf(...))

# Change partitioning
.partitionBy("attack_category", "partition_date")
```

#### 1.3 Update Docker Compose
**File**: `docker/docker-compose.consumer.yaml`

Add aggregator service:
```yaml
aggregator:
  build:
    context: ../
    dockerfile: docker/Dockerfile.consumer
  environment:
    - INPUT_TOPIC=raw-cicids
    - OUTPUT_TOPIC=security-alerts
  command: /opt/spark/bin/spark-submit --packages $SPARK_PACKAGES src/aggregator.py
```

---

### Phase 2: SQL Query Layer (Day 2-3)

#### 2.1 Deploy Trino
**File**: `docker/docker-compose.superset.yaml`

Services:
```yaml
trino-coordinator:
  image: trinodb/trino:436
  ports: ["8080:8080"]
  volumes:
    - ./trino/catalog:/etc/trino/catalog
    - ./trino/config.properties:/etc/trino/config.properties
```

#### 2.2 Configure Trino Hive Connector
**File**: `docker/trino/catalog/hive.properties`

```properties
connector.name=hive
hive.metastore=file
hive.metastore.catalog.dir=/tmp/hive-metastore
hive.s3.endpoint=http://minio:9000
hive.s3.path-style-access=true
hive.s3.aws-access-key=admin
hive.s3.aws-secret-key=password
hive.parquet.use-column-names=true
```

#### 2.3 Create Table Definitions
**File**: `scripts/create_trino_tables.sql`

```sql
CREATE SCHEMA IF NOT EXISTS hive.security_logs
WITH (location = 's3a://data/');

CREATE TABLE hive.security_logs.normalized_logs (
    destination_port BIGINT,
    flow_duration BIGINT,
    label VARCHAR,
    attack_category VARCHAR,
    severity_level VARCHAR,
    risk_score INTEGER,
    partition_date VARCHAR
    -- ... all other fields
) WITH (
    external_location = 's3a://data/normalized-logs/',
    format = 'PARQUET',
    partitioned_by = ARRAY['attack_category', 'partition_date']
);

-- Create views for common queries
CREATE VIEW hive.security_logs.recent_attacks AS
SELECT attack_category, label, COUNT(*) as count
FROM hive.security_logs.normalized_logs
WHERE partition_date >= DATE_FORMAT(CURRENT_DATE - INTERVAL '1' DAY, '%Y-%m-%d')
GROUP BY attack_category, label;
```

---

### Phase 3: Superset Visualization (Day 3-4)

#### 3.1 Deploy Superset Stack
**File**: `docker/docker-compose.superset.yaml`

Services:
- `superset-db` (PostgreSQL metadata)
- `redis` (caching)
- `superset-init` (initialize DB, create admin)
- `superset` (main UI, port 8088)

#### 3.2 Configure Superset
**File**: `docker/superset/superset_config.py`

Key settings:
```python
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://superset:superset@superset-db:5432/superset'
CACHE_CONFIG = {'CACHE_TYPE': 'RedisCache', 'CACHE_REDIS_HOST': 'redis'}
FEATURE_FLAGS = {
    'DASHBOARD_NATIVE_FILTERS': True,
    'DASHBOARD_CROSS_FILTERS': True
}
```

#### 3.3 Connect to Trino
**Superset UI**: Settings → Database Connections → + Database

**SQLAlchemy URI**:
```
trino://trino-coordinator:8080/hive/security_logs
```

#### 3.4 Build Dashboard

**Charts to create**:
1. **Big Number**: Total attacks (24h) - `SUM(attack_count)` from `recent_attacks`
2. **Pie Chart**: Attack distribution by category
3. **Time Series**: Attack volume over time (hourly)
4. **Bar Chart**: Top 10 attack types
5. **Table**: Top 20 attacking sources (if src_ip added)
6. **Heatmap**: Attack intensity by hour/day

---

### Phase 4: Monitoring & Documentation (Day 5)

#### 4.1 Alert Consumer
**File**: `src/alert_consumer.py`

```python
from confluent_kafka import Consumer

consumer = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'alert-display',
    'auto.offset.reset': 'latest'
})
consumer.subscribe(['security-alerts'])

while True:
    msg = consumer.poll(1.0)
    if msg:
        print(f"🚨 ALERT: {msg.value()}")
```

#### 4.2 Sample SQL Queries
**Directory**: `queries/`

Create files:
- `top_attackers.sql` - Most active malicious sources
- `attack_timeline.sql` - Hourly breakdown by type
- `anomaly_summary.sql` - Detected anomalies
- `ddos_analysis.sql` - DDoS pattern analysis

#### 4.3 Update README
**File**: `README.md`

Add sections:
- Updated architecture diagram (from this plan)
- Service endpoints table
- Analytics features description
- Quick start guide
- Dashboard screenshots

---

## Service Endpoints

| Service | Port | URL | Credentials |
|---------|------|-----|-------------|
| Kafka | 9092 | localhost:9092 | - |
| MinIO Console | 9001 | http://localhost:9001 | admin/password |
| Trino UI | 8080 | http://localhost:8080 | - |
| Superset | 8088 | http://localhost:8088 | admin/admin |

---

## Verification Checklist

### ✅ Data Pipeline
- [ ] Producer sends events to Kafka `raw-cicids` topic
- [ ] Consumer writes Parquet files to `s3://data/normalized-logs/attack_category=*/partition_date=*/`
- [ ] Aggregator writes to `s3://data/aggregations-5min/`
- [ ] Anomaly alerts appear in Kafka `security-alerts` topic

### ✅ Query Layer
- [ ] Trino UI accessible at http://localhost:8080
- [ ] Can execute: `SELECT * FROM hive.security_logs.normalized_logs LIMIT 10;`
- [ ] Partition pruning works: `WHERE attack_category = 'DDoS'`

### ✅ Visualization
- [ ] Superset accessible at http://localhost:8088
- [ ] Database connection to Trino successful
- [ ] Datasets created for tables and views
- [ ] Dashboard displays real-time metrics

### ✅ Monitoring
- [ ] Alert consumer displays anomalies from Kafka
- [ ] Sample SQL queries run successfully
- [ ] All services healthy: `docker compose ps`

---

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **SQL Engine** | Trino | Fast ad-hoc queries on Parquet, better than Spark SQL for interactive analytics |
| **Metastore** | File-based Hive | Simpler than separate Hive Metastore service, sufficient for mini project |
| **BI Tool** | Apache Superset | Purpose-built for data exploration, richer visualizations than Grafana |
| **Windowing** | Tumbling (5-min) | Non-overlapping windows, clear distinct periods for analysis |
| **Partitioning** | attack_category + date | Enables efficient query pruning for both time-range and category filters |
| **Alert Distribution** | Kafka topic | Demonstrates pub-sub pattern, allows multiple consumers (dashboards, notifications, etc.) |

---

## File Structure After Implementation

```
bigdata-hcmut/
├── README.md                          # Updated with new architecture
├── IMPLEMENTATION_PLAN.md             # This file
├── requirements.txt
├── docker/
│   ├── docker-compose.yaml            # Main orchestration (includes all below)
│   ├── docker-compose.kafka.yaml
│   ├── docker-compose.minio.yaml
│   ├── docker-compose.consumer.yaml   # Updated with aggregator
│   ├── docker-compose.superset.yaml   # NEW: Trino + Superset stack
│   ├── Dockerfile.producer
│   ├── Dockerfile.consumer
│   ├── trino/
│   │   ├── config.properties          # NEW: Trino coordinator config
│   │   └── catalog/
│   │       └── hive.properties        # NEW: S3/MinIO connector
│   └── superset/
│       ├── superset_config.py         # NEW: Superset configuration
│       └── dashboards/
│           └── security_dashboard.json # NEW: Dashboard definition
├── src/
│   ├── producer.py
│   ├── consumer.py                    # ENHANCED: attack classification
│   ├── aggregator.py                  # NEW: windowed aggregations
│   └── alert_consumer.py              # NEW: display alerts
├── scripts/
│   ├── create_trino_tables.sql        # NEW: table definitions
│   └── init_superset.sh               # NEW: automated setup
└── queries/
    ├── README.md                      # NEW: query documentation
    ├── top_attackers.sql              # NEW: sample queries
    ├── attack_timeline.sql
    ├── anomaly_summary.sql
    └── ddos_analysis.sql
```

---

## Startup Commands

```bash
# 1. Start entire stack
docker compose -f docker/docker-compose.yaml up --build -d

# 2. Wait for services to initialize (~60 seconds)
docker compose ps

# 3. Initialize Trino tables
docker exec -it trino-coordinator trino -f /scripts/create_trino_tables.sql

# 4. Access Superset and configure database connection
open http://localhost:8088

# 5. Monitor alerts (separate terminal)
python src/alert_consumer.py

# 6. Check data in MinIO
open http://localhost:9001
```

---

## Learning Outcomes (Big Data Course)

This project demonstrates:

1. **Stream Processing**: Kafka + Spark Structured Streaming with windowing and watermarks
2. **Data Lake**: S3-compatible storage with Parquet columnar format and partitioning
3. **Real-Time Analytics**: Stateful stream processing with anomaly detection
4. **Query Optimization**: Partition pruning, predicate pushdown in distributed queries
5. **Data Enrichment**: Classification, risk scoring, derived attributes
6. **Lambda Architecture Concepts**: Speed layer (streaming) + serving layer (batch queries)
7. **Modern Data Stack**: Producer → Queue → Processor → Lake → Query Engine → BI Tool

---

**Timeline**: 5 days  
**Difficulty**: Intermediate  
**Team Size**: 1-3 students  
**Demo**: Live dashboard + alert monitoring + SQL queries
