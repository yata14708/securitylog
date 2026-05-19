"""
Spark Job 1 — Normalizer
========================
Reads from raw-cicids, raw-unsw, raw-cicdos Kafka topics.
Maps each dataset's fields → unified schema.
Enriches with attack_category + severity_level.
Writes Parquet to MinIO  (s3a://data/normalized-logs/)
  partitioned by attack_category + partition_date.
Forwards enriched events to logs-normalized Kafka topic.
Micro-batch trigger: 30 seconds.
"""

import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, current_timestamp, to_date, date_format,
    to_json, struct, lit, udf, coalesce, when
)
from pyspark.sql.types import (
    StructType, StructField, StringType, LongType, DoubleType
)

# ---------------------------------------------------------------------------
# Unified raw schema (producer sends this for every dataset)
# ---------------------------------------------------------------------------
RAW_SCHEMA = StructType([
    StructField("src_ip",             StringType(), True),
    StructField("dst_ip",             StringType(), True),
    StructField("src_port",           StringType(), True),
    StructField("dst_port",           StringType(), True),
    StructField("protocol",           StringType(), True),
    StructField("flow_duration",      StringType(), True),
    StructField("total_fwd_packets",  StringType(), True),
    StructField("total_bwd_packets",  StringType(), True),
    StructField("flow_bytes_s",       StringType(), True),
    StructField("flow_packets_s",     StringType(), True),
    StructField("syn_flag_count",     StringType(), True),
    StructField("label",              StringType(), True),
    StructField("dataset_source",     StringType(), True),
    StructField("produced_at_ts",     LongType(),   True),
])

# ---------------------------------------------------------------------------
# UDFs
# ---------------------------------------------------------------------------

def _classify(label, source):
    if not label:
        return "Unknown"
    u = label.strip().upper()
    # BENIGN
    if u in ("BENIGN", "0", "NORMAL"):
        return "Benign"
    # DDoS / DoS
    if "DDOS" in u or "DRDOS" in u:
        return "DDoS"
    if u in ("SYN",):
        return "DDoS_SYN"
    if "UDP" in u and "LAG" not in u:
        return "DDoS_UDP"
    if "UDPLAG" in u:
        return "DDoS_UDPLag"
    if "LDAP" in u:
        return "DDoS_LDAP"
    if "MSSQL" in u:
        return "DDoS_MSSQL"
    if "NETBIOS" in u:
        return "DDoS_NetBIOS"
    if "NTP" in u:
        return "DDoS_NTP"
    if "SNMP" in u:
        return "DDoS_SNMP"
    if "SSDP" in u:
        return "DDoS_SSDP"
    if "TFTP" in u:
        return "DDoS_TFTP"
    if "DNS" in u:
        return "DDoS_DNS"
    if "PORTMAP" in u:
        return "DDoS_Portmap"
    if "DOS" in u:
        return "DoS"
    # Web attacks
    if "WEB ATTACK" in u or "WEB_ATTACK" in u:
        if "BRUTE" in u:
            return "Web_Attack_BruteForce"
        if "XSS" in u:
            return "Web_Attack_XSS"
        if "SQL" in u:
            return "Web_Attack_SQLi"
        return "Web_Attack"
    # Specific types
    if "PORTSCAN" in u:
        return "Reconnaissance"
    if "RECONNAISSANCE" in u:
        return "Reconnaissance"
    if "BOT" in u:
        return "Botnet"
    if "INFILTRATION" in u:
        return "Infiltration"
    if "PATATOR" in u:
        return "Credential_Attack"
    if "HEARTBLEED" in u:
        return "Exploits"
    if "EXPLOITS" in u:
        return "Exploits"
    if "BACKDOOR" in u:
        return "Backdoor"
    if "SHELLCODE" in u:
        return "Shellcode"
    if "WORMS" in u:
        return "Worms"
    if "FUZZERS" in u:
        return "Fuzzers"
    if "GENERIC" in u:
        return "Generic"
    if "ANALYSIS" in u:
        return "Analysis"
    if u == "1":
        return "Attack"
    return "Other"


def _severity(category):
    if not category:
        return "Unknown"
    c = category.upper()
    if c == "BENIGN":
        return "Benign"
    if any(x in c for x in ["DDOS", "SYN", "MSSQL", "NETBIOS", "NTP", "SNMP",
                              "SSDP", "TFTP", "DNS", "PORTMAP", "LDAP"]):
        return "Critical"
    if any(x in c for x in ["EXPLOITS", "SHELLCODE", "BACKDOOR", "WORMS", "BOTNET"]):
        return "High"
    if any(x in c for x in ["WEB_ATTACK", "CREDENTIAL", "DOS"]):
        return "High"
    if any(x in c for x in ["RECONNAISSANCE", "INFILTRATION", "FUZZERS", "ANALYSIS"]):
        return "Medium"
    if "GENERIC" in c:
        return "Low"
    return "Unknown"


classify_udf  = udf(_classify,  StringType())
severity_udf  = udf(_severity,  StringType())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    kafka_servers   = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    minio_endpoint  = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
    minio_user      = os.environ.get("MINIO_ACCESS_KEY", "admin")
    minio_password  = os.environ.get("MINIO_SECRET_KEY", "password")
    input_topics    = os.environ.get("INPUT_TOPICS", "raw-cicids,raw-unsw,raw-cicdos")
    output_topic    = os.environ.get("OUTPUT_TOPIC", "logs-normalized")
    output_path     = "s3a://data/normalized-logs/"
    checkpoint_path = "s3a://data/checkpoints/normalizer/"

    packages = (
        "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.2,"
        "org.apache.hadoop:hadoop-aws:3.3.4,"
        "com.amazonaws:aws-java-sdk-bundle:1.12.262"
    )

    spark = (
        SparkSession.builder
        .appName("Job1-Normalizer")
        .config("spark.jars.packages", packages)
        .config("spark.hadoop.fs.s3a.endpoint",              minio_endpoint)
        .config("spark.hadoop.fs.s3a.access.key",            minio_user)
        .config("spark.hadoop.fs.s3a.secret.key",            minio_password)
        .config("spark.hadoop.fs.s3a.path.style.access",     "true")
        .config("spark.hadoop.fs.s3a.impl",                  "org.apache.hadoop.fs.s3a.S3AFileSystem")
        .config("spark.hadoop.fs.s3a.aws.credentials.provider",
                "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider")
        .config("spark.hadoop.fs.s3a.connection.ssl.enabled","false")
        .config("spark.sql.shuffle.partitions",              "6")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    # ---- Read from Kafka ----
    raw = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", kafka_servers)
        .option("subscribe", input_topics)
        .option("startingOffsets", "earliest")
        .option("failOnDataLoss", "false")
        .load()
    )

    # ---- Parse JSON ----
    parsed = (
        raw
        .selectExpr("CAST(value AS STRING) AS json_str", "topic")
        .select(from_json(col("json_str"), RAW_SCHEMA).alias("d"), col("topic"))
        .select("d.*", "topic")
    )

    # ---- Enrich ----
    enriched = (
        parsed
        .withColumn("attack_category",
                    classify_udf(col("label"), col("dataset_source")))
        .withColumn("severity_level",
                    severity_udf(col("attack_category")))
        .withColumn("event_timestamp", current_timestamp())
        .withColumn("partition_date",  date_format(current_timestamp(), "yyyy-MM-dd"))
        # Cast numeric fields
        .withColumn("src_port",          col("src_port").cast(LongType()))
        .withColumn("dst_port",          col("dst_port").cast(LongType()))
        .withColumn("flow_duration",     col("flow_duration").cast(DoubleType()))
        .withColumn("total_fwd_packets", col("total_fwd_packets").cast(LongType()))
        .withColumn("total_bwd_packets", col("total_bwd_packets").cast(LongType()))
        .withColumn("flow_bytes_s",      col("flow_bytes_s").cast(DoubleType()))
        .withColumn("flow_packets_s",    col("flow_packets_s").cast(DoubleType()))
        .withColumn("syn_flag_count",    col("syn_flag_count").cast(LongType()))
        .drop("topic")
    )

    # ---- foreachBatch: write Parquet + forward to Kafka ----
    def process_batch(batch_df, batch_id):
        if batch_df.isEmpty():
            return

        # 1) Write Parquet to MinIO
        (
            batch_df
            .write
            .mode("append")
            .partitionBy("attack_category", "partition_date")
            .parquet(output_path)
        )

        # 2) Forward to logs-normalized Kafka topic
        (
            batch_df
            .select(
                col("src_ip").alias("key"),
                to_json(struct("*")).alias("value")
            )
            .write
            .format("kafka")
            .option("kafka.bootstrap.servers", kafka_servers)
            .option("topic", output_topic)
            .save()
        )

        print(f"[Normalizer] Batch {batch_id}: wrote {batch_df.count()} rows")

    query = (
        enriched
        .writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", checkpoint_path)
        .trigger(processingTime="30 seconds")
        .start()
    )

    try:
        query.awaitTermination()
    except KeyboardInterrupt:
        query.stop()


if __name__ == "__main__":
    main()
