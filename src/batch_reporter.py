"""
Spark Job 3 — Batch Reporter
=============================
Batch-reads normalized logs and aggregations from MinIO.
Generates report Parquet files under s3a://data/reports/:
  - attack_distribution/
  - hourly_timeseries/
  - behavioral_profiles/
  - benign_baseline/
Runs in a loop every REPORT_INTERVAL_SECONDS (default 300).
"""

import os
import time
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, count, avg, sum as spark_sum, max as spark_max,
    date_trunc, hour, desc, lit, current_timestamp
)


def run_reports(spark, normalized_path, aggregations_path, reports_path):
    print(f"[BatchReporter] Running reports at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        norm = spark.read.parquet(normalized_path)
    except Exception as e:
        print(f"[BatchReporter] No normalized data yet: {e}")
        return

    total = norm.count()
    if total == 0:
        print("[BatchReporter] No records yet, skipping.")
        return

    print(f"[BatchReporter] Total normalized records: {total:,}")

    # ---- 1. Attack distribution ----
    attack_dist = (
        norm
        .groupBy("attack_category", "severity_level", "dataset_source")
        .agg(count("*").alias("event_count"))
        .orderBy(desc("event_count"))
    )
    attack_dist.write.mode("overwrite").parquet(f"{reports_path}attack_distribution/")
    print("[BatchReporter] attack_distribution done")

    # ---- 2. Hourly time series ----
    hourly = (
        norm
        .withColumn("hour_bucket", date_trunc("hour", col("event_timestamp")))
        .groupBy("hour_bucket", "attack_category", "dataset_source")
        .agg(count("*").alias("event_count"))
        .orderBy("hour_bucket")
    )
    hourly.write.mode("overwrite").parquet(f"{reports_path}hourly_timeseries/")
    print("[BatchReporter] hourly_timeseries done")

    # ---- 3. Behavioral profiles (top src_ip) ----
    profiles = (
        norm
        .groupBy("src_ip", "dataset_source")
        .agg(
            count("*").alias("total_events"),
            count(col("attack_category") != "Benign").alias("attack_events"),
            avg("flow_duration").alias("avg_flow_duration"),
            avg("flow_bytes_s").alias("avg_flow_bytes_s"),
            spark_sum("syn_flag_count").alias("total_syn_flags"),
        )
        .filter(col("src_ip").isNotNull())
        .orderBy(desc("total_events"))
        .limit(10000)
    )
    profiles.write.mode("overwrite").parquet(f"{reports_path}behavioral_profiles/")
    print("[BatchReporter] behavioral_profiles done")

    # ---- 4. Benign baseline stats ----
    benign = norm.filter(col("attack_category") == "Benign")
    if benign.count() > 0:
        baseline = (
            benign
            .agg(
                count("*").alias("benign_count"),
                avg("flow_duration").alias("avg_flow_duration"),
                avg("flow_bytes_s").alias("avg_flow_bytes_s"),
                avg("flow_packets_s").alias("avg_flow_packets_s"),
                avg("total_fwd_packets").alias("avg_fwd_packets"),
                avg("total_bwd_packets").alias("avg_bwd_packets"),
                spark_max("flow_bytes_s").alias("max_flow_bytes_s"),
            )
            .withColumn("generated_at", current_timestamp())
        )
        baseline.write.mode("overwrite").parquet(f"{reports_path}benign_baseline/")
        print("[BatchReporter] benign_baseline done")

    # ---- 5. Aggregation summary (if data exists) ----
    try:
        agg_df = spark.read.parquet(aggregations_path)
        agg_summary = (
            agg_df
            .groupBy("dataset_source", "window_start_date")
            .agg(
                count("*").alias("window_count"),
                spark_sum("event_count").alias("total_events"),
                avg("avg_flow_bytes_s").alias("avg_flow_bytes_s"),
                count(col("is_alert") == True).alias("alert_windows"),
            )
            .orderBy("window_start_date")
        )
        agg_summary.write.mode("overwrite").parquet(f"{reports_path}aggregation_summary/")
        print("[BatchReporter] aggregation_summary done")
    except Exception as e:
        print(f"[BatchReporter] No aggregation data yet: {e}")

    print("[BatchReporter] All reports complete.")


def main():
    minio_endpoint  = os.environ.get("MINIO_ENDPOINT",    "http://minio:9000")
    minio_user      = os.environ.get("MINIO_ACCESS_KEY",  "admin")
    minio_password  = os.environ.get("MINIO_SECRET_KEY",  "password")
    interval        = int(os.environ.get("REPORT_INTERVAL_SECONDS", "300"))

    normalized_path   = "s3a://data/normalized-logs/"
    aggregations_path = "s3a://data/aggregations-5min/"
    reports_path      = "s3a://data/reports/"

    packages = (
        "org.apache.hadoop:hadoop-aws:3.3.4,"
        "com.amazonaws:aws-java-sdk-bundle:1.12.262"
    )

    spark = (
        SparkSession.builder
        .appName("Job3-BatchReporter")
        .config("spark.jars.packages", packages)
        .config("spark.hadoop.fs.s3a.endpoint",              minio_endpoint)
        .config("spark.hadoop.fs.s3a.access.key",            minio_user)
        .config("spark.hadoop.fs.s3a.secret.key",            minio_password)
        .config("spark.hadoop.fs.s3a.path.style.access",     "true")
        .config("spark.hadoop.fs.s3a.impl",
                "org.apache.hadoop.fs.s3a.S3AFileSystem")
        .config("spark.hadoop.fs.s3a.aws.credentials.provider",
                "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider")
        .config("spark.hadoop.fs.s3a.connection.ssl.enabled","false")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    print(f"[BatchReporter] Starting. Will run every {interval}s.")
    while True:
        try:
            run_reports(spark, normalized_path, aggregations_path, reports_path)
        except Exception as e:
            print(f"[BatchReporter] Error: {e}")
        print(f"[BatchReporter] Sleeping {interval}s...")
        time.sleep(interval)


if __name__ == "__main__":
    main()
