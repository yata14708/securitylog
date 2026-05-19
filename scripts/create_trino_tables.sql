-- =============================================================
-- Trino DDL — Security Log Pipeline
-- Run once after Trino starts (via trino-init service).
-- =============================================================

-- ── Schema ────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS hive.security_logs
WITH (location = 's3://data/');

-- ── Table 1: Normalised logs ───────────────────────────────────
CREATE TABLE IF NOT EXISTS hive.security_logs.normalized_logs (
    src_ip             VARCHAR,
    dst_ip             VARCHAR,
    src_port           BIGINT,
    dst_port           BIGINT,
    protocol           VARCHAR,
    flow_duration      DOUBLE,
    total_fwd_packets  BIGINT,
    total_bwd_packets  BIGINT,
    flow_bytes_s       DOUBLE,
    flow_packets_s     DOUBLE,
    syn_flag_count     BIGINT,
    label              VARCHAR,
    severity_level     VARCHAR,
    dataset_source     VARCHAR,
    event_timestamp    TIMESTAMP,
    produced_at_ts     BIGINT,
    processed_at       TIMESTAMP,
    -- partition columns last
    attack_category    VARCHAR,
    partition_date     VARCHAR
)
WITH (
    external_location = 's3://data/normalized-logs/',
    format            = 'PARQUET',
    partitioned_by    = ARRAY['attack_category', 'partition_date']
);

-- Sync partitions from storage


-- ── Table 2: 5-minute aggregations ────────────────────────────
CREATE TABLE IF NOT EXISTS hive.security_logs.aggregations_5min (
    src_ip              VARCHAR,
    dataset_source      VARCHAR,
    event_count         BIGINT,
    unique_labels       BIGINT,
    unique_dst_ports    BIGINT,
    avg_flow_duration   DOUBLE,
    avg_flow_bytes_s    DOUBLE,
    total_syn_flags     BIGINT,
    total_fwd_packets   BIGINT,
    syn_flag_ratio      DOUBLE,
    window_start        TIMESTAMP,
    window_end          TIMESTAMP,
    is_alert            BOOLEAN,
    alert_reason        VARCHAR,
    processed_at        TIMESTAMP,
    -- partition columns last
    window_start_date   VARCHAR
)
WITH (
    external_location = 's3://data/aggregations-5min/',
    format            = 'PARQUET',
    partitioned_by    = ARRAY['window_start_date', 'dataset_source']
);



-- ── Table 3: Attack distribution report ───────────────────────
CREATE TABLE IF NOT EXISTS hive.security_logs.report_attack_distribution (
    attack_category  VARCHAR,
    severity_level   VARCHAR,
    dataset_source   VARCHAR,
    event_count      BIGINT
)
WITH (
    external_location = 's3://data/reports/attack_distribution/',
    format            = 'PARQUET'
);

-- ── Table 4: Hourly time series report ────────────────────────
CREATE TABLE IF NOT EXISTS hive.security_logs.report_hourly_timeseries (
    hour_bucket      TIMESTAMP,
    attack_category  VARCHAR,
    dataset_source   VARCHAR,
    event_count      BIGINT
)
WITH (
    external_location = 's3://data/reports/hourly_timeseries/',
    format            = 'PARQUET'
);

-- ── Table 5: Behavioural profiles ─────────────────────────────
CREATE TABLE IF NOT EXISTS hive.security_logs.report_behavioral_profiles (
    src_ip            VARCHAR,
    dataset_source    VARCHAR,
    total_events      BIGINT,
    attack_events     BIGINT,
    avg_flow_duration DOUBLE,
    avg_flow_bytes_s  DOUBLE,
    total_syn_flags   BIGINT
)
WITH (
    external_location = 's3://data/reports/behavioral_profiles/',
    format            = 'PARQUET'
);

-- ── Useful Views ──────────────────────────────────────────────

-- Recent attacks (last 24 h)
CREATE OR REPLACE VIEW hive.security_logs.recent_attacks AS
SELECT
    attack_category,
    severity_level,
    label,
    dataset_source,
    COUNT(*) AS event_count
FROM hive.security_logs.normalized_logs
WHERE partition_date >= CAST(current_date - INTERVAL '1' DAY AS VARCHAR)
  AND attack_category <> 'Benign'
GROUP BY attack_category, severity_level, label, dataset_source
ORDER BY event_count DESC;

-- Top attacking source IPs (all time)
CREATE OR REPLACE VIEW hive.security_logs.top_src_ips AS
SELECT
    src_ip,
    dataset_source,
    COUNT(*) AS total_events,
    COUNT_IF(attack_category <> 'Benign') AS attack_events,
    MAX(syn_flag_count) AS max_syn_flag_count
FROM hive.security_logs.normalized_logs
WHERE src_ip IS NOT NULL
GROUP BY src_ip, dataset_source
ORDER BY attack_events DESC
LIMIT 1000;

-- Hourly traffic summary
CREATE OR REPLACE VIEW hive.security_logs.hourly_traffic AS
SELECT
    date_trunc('hour', event_timestamp) AS hour_bucket,
    attack_category,
    dataset_source,
    COUNT(*) AS event_count,
    AVG(flow_bytes_s) AS avg_flow_bytes_s
FROM hive.security_logs.normalized_logs
GROUP BY 1, 2, 3
ORDER BY 1 DESC;

-- Active alerts (last 6 h)
CREATE OR REPLACE VIEW hive.security_logs.active_alerts AS
SELECT
    src_ip,
    dataset_source,
    event_count,
    syn_flag_ratio,
    alert_reason,
    window_start,
    window_end
FROM hive.security_logs.aggregations_5min
WHERE is_alert = true
  AND window_start_date >= CAST(current_date - INTERVAL '1' DAY AS VARCHAR)
ORDER BY window_start DESC;
