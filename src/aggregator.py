"""
Spark Job 2 — Aggregator
========================
Reads from logs-normalized Kafka topic.
Computes 5-minute tumbling windows per src_ip with 2-min watermark.
Writes all window aggregations to MinIO s3a://data/aggregations-5min/
Writes alert rows only to logs-alerts Kafka topic.
"""

import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, window, count, avg, sum as spark_sum,
    countDistinct, to_json, struct, when, current_timestamp, date_format
)
from pyspark.sql.types import (
    StructType, StructField, StringType, LongType, DoubleType, TimestampType
)

UNIFIED_SCHEMA = StructType([
    StructField("src_ip",            StringType(),    True),
    StructField("dst_ip",            StringType(),    True),
    StructField("src_port",          LongType(),      True),
    StructField("dst_port",          LongType(),      True),
    StructField("protocol",          StringType(),    True),
    StructField("flow_duration",     DoubleType(),    True),
    StructField("total_fwd_packets", LongType(),      True),
    StructField("total_bwd_packets", LongType(),      True),
    StructField("flow_bytes_s",      DoubleType(),    True),
    StructField("flow_packets_s",    DoubleType(),    True),
    StructField("syn_flag_count",    LongType(),      True),
    StructField("label",             StringType(),    True),
    StructField("attack_category",   StringType(),    True),
    StructField("severity_level",    StringType(),    True),
    StructField("dataset_source",    StringType(),    True),
    StructField("event_timestamp",   TimestampType(), True),
    StructField("partition_date",    StringType(),    True),
])

THRESHOLD_EVENTS = int(os.environ.get("ALERT_THRESHOLD_EVENTS", "500"))
THRESHOLD_SYN    = float(os.environ.get("ALERT_THRESHOLD_SYN",    "0.8"))


def main():
    kafka_servers   = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    minio_endpoint  = os.environ.get("MINIO_ENDPOINT",    "http://minio:9000")
    minio_user      = os.environ.get("MINIO_ACCESS_KEY",  "admin")
    minio_password  = os.environ.get("MINIO_SECRET_KEY",  "password")
    input_topic     = os.environ.get("INPUT_TOPIC",        "logs-normalized")
    alert_topic     = os.environ.get("ALERT_TOPIC",        "logs-alerts")
    output_path     = "s3a://data/aggregations-5min/"
    checkpoint_path = "s3a://data/checkpoints/aggregator/"

    packages = (
        "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.2,"
        "org.apache.hadoop:hadoop-aws:3.3.4,"
        "com.amazonaws:aws-java-sdk-bundle:1.12.262"
    )

    spark = (
        SparkSession.builder
        .appName("Job2-Aggregator")
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
        .config("spark.sql.shuffle.partitions", "6")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    raw = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", kafka_servers)
        .option("subscribe", input_topic)
        .option("startingOffsets", "earliest")
        .option("failOnDataLoss", "false")
        .load()
    )

    events = (
        raw
        .selectExpr("CAST(value AS STRING) AS json_str")
        .select(from_json(col("json_str"), UNIFIED_SCHEMA).alias("d"))
        .select("d.*")
        .withWatermark("event_timestamp", "2 minutes")
    )

    agg = (
        events
        .groupBy(
            window(col("event_timestamp"), "5 minutes"),
            col("src_ip"),
            col("dataset_source"),
        )
        .agg(
            count("*").alias("event_count"),
            countDistinct("label").alias("unique_labels"),
            countDistinct("dst_port").alias("unique_dst_ports"),
            avg("flow_duration").alias("avg_flow_duration"),
            avg("flow_bytes_s").alias("avg_flow_bytes_s"),
            spark_sum("syn_flag_count").alias("total_syn_flags"),
            spark_sum("total_fwd_packets").alias("total_fwd_packets"),
        )
        .withColumn(
            "syn_flag_ratio",
            when(col("total_fwd_packets") > 0,
                 col("total_syn_flags") / col("total_fwd_packets"))
            .otherwise(0.0)
        )
        .withColumn("window_start",      col("window.start"))
        .withColumn("window_end",        col("window.end"))
        .withColumn("window_start_date", date_format(col("window.start"), "yyyy-MM-dd"))
        .drop("window")
        .withColumn(
            "is_alert",
            (col("event_count") > THRESHOLD_EVENTS) |
            (col("syn_flag_ratio") > THRESHOLD_SYN)
        )
        .withColumn(
            "alert_reason",
            when((col("event_count") > THRESHOLD_EVENTS) &
                 (col("syn_flag_ratio") > THRESHOLD_SYN), "HIGH_VOLUME+SYN_FLOOD")
            .when(col("event_count") > THRESHOLD_EVENTS, "HIGH_VOLUME")
            .when(col("syn_flag_ratio") > THRESHOLD_SYN, "SYN_FLOOD")
            .otherwise(None)
        )
        .withColumn("processed_at", current_timestamp())
    )

    def process_batch(batch_df, batch_id):
        if batch_df.isEmpty():
            return
        batch_df.write.mode("append") \
            .partitionBy("window_start_date", "dataset_source") \
            .parquet(output_path)

        alerts = batch_df.filter(col("is_alert") == True)
        if not alerts.isEmpty():
            alerts.select(
                col("src_ip").alias("key"),
                to_json(struct("*")).alias("value")
            ).write \
                .format("kafka") \
                .option("kafka.bootstrap.servers", kafka_servers) \
                .option("topic", alert_topic) \
                .save()
            print(f"[Aggregator] Batch {batch_id}: {alerts.count()} alerts sent")
        print(f"[Aggregator] Batch {batch_id}: done")

    query = (
        agg.writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", checkpoint_path)
        .trigger(processingTime="30 seconds")
        .outputMode("update")
        .start()
    )

    try:
        query.awaitTermination()
    except KeyboardInterrupt:
        query.stop()


if __name__ == "__main__":
    main()
