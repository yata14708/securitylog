import os
from pyspark.sql import SparkSession
from pyspark.sql.functions import from_json, col, current_timestamp
from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType

def main():
    kafka_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    minio_endpoint = os.environ.get("MINIO_ENDPOINT", "http://localhost:9000")
    topic_name = os.environ.get("KAFKA_TOPIC", "raw-cicids")

    packages = "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.2,org.apache.hadoop:hadoop-aws:3.3.4,com.amazonaws:aws-java-sdk-bundle:1.12.262"
    
    spark = SparkSession.builder \
        .appName("LogNormalizationJob") \
        .config("spark.jars.packages", packages) \
        .config("spark.hadoop.fs.s3a.endpoint", minio_endpoint) \
        .config("spark.hadoop.fs.s3a.access.key", "admin") \
        .config("spark.hadoop.fs.s3a.secret.key", "password") \
        .config("spark.hadoop.fs.s3a.path.style.access", "true") \
        .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem") \
        .config("spark.hadoop.fs.s3a.aws.credentials.provider", "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider") \
        .config("spark.sql.shuffle.partitions", "3") \
        .getOrCreate()
        
    spark.sparkContext.setLogLevel("WARN")

    # CICIDS2017 schema (sanitized for Parquet)
    schema = StructType([
        StructField("destination_port", StringType(), True),
        StructField("flow_duration", StringType(), True),
        StructField("total_fwd_packets", StringType(), True),
        StructField("total_backward_packets", StringType(), True),
        StructField("total_length_of_fwd_packets", StringType(), True),
        StructField("total_length_of_bwd_packets", StringType(), True),
        StructField("fwd_packet_length_max", StringType(), True),
        StructField("fwd_packet_length_min", StringType(), True),
        StructField("fwd_packet_length_mean", StringType(), True),
        StructField("fwd_packet_length_std", StringType(), True),
        StructField("bwd_packet_length_max", StringType(), True),
        StructField("bwd_packet_length_min", StringType(), True),
        StructField("bwd_packet_length_mean", StringType(), True),
        StructField("bwd_packet_length_std", StringType(), True),
        StructField("flow_bytes_s", StringType(), True),
        StructField("flow_packets_s", StringType(), True),
        StructField("flow_iat_mean", StringType(), True),
        StructField("flow_iat_std", StringType(), True),
        StructField("flow_iat_max", StringType(), True),
        StructField("flow_iat_min", StringType(), True),
        StructField("fwd_iat_total", StringType(), True),
        StructField("fwd_iat_mean", StringType(), True),
        StructField("fwd_iat_std", StringType(), True),
        StructField("fwd_iat_max", StringType(), True),
        StructField("fwd_iat_min", StringType(), True),
        StructField("bwd_iat_total", StringType(), True),
        StructField("bwd_iat_mean", StringType(), True),
        StructField("bwd_iat_std", StringType(), True),
        StructField("bwd_iat_max", StringType(), True),
        StructField("bwd_iat_min", StringType(), True),
        StructField("fwd_psh_flags", StringType(), True),
        StructField("bwd_psh_flags", StringType(), True),
        StructField("fwd_urg_flags", StringType(), True),
        StructField("bwd_urg_flags", StringType(), True),
        StructField("fwd_header_length", StringType(), True),
        StructField("bwd_header_length", StringType(), True),
        StructField("fwd_packets_s", StringType(), True),
        StructField("bwd_packets_s", StringType(), True),
        StructField("min_packet_length", StringType(), True),
        StructField("max_packet_length", StringType(), True),
        StructField("packet_length_mean", StringType(), True),
        StructField("packet_length_std", StringType(), True),
        StructField("packet_length_variance", StringType(), True),
        StructField("fin_flag_count", StringType(), True),
        StructField("syn_flag_count", StringType(), True),
        StructField("rst_flag_count", StringType(), True),
        StructField("psh_flag_count", StringType(), True),
        StructField("ack_flag_count", StringType(), True),
        StructField("urg_flag_count", StringType(), True),
        StructField("cwe_flag_count", StringType(), True),
        StructField("ece_flag_count", StringType(), True),
        StructField("down_up_ratio", StringType(), True),
        StructField("average_packet_size", StringType(), True),
        StructField("avg_fwd_segment_size", StringType(), True),
        StructField("avg_bwd_segment_size", StringType(), True),
        StructField("fwd_avg_bytes_bulk", StringType(), True),
        StructField("fwd_avg_packets_bulk", StringType(), True),
        StructField("fwd_avg_bulk_rate", StringType(), True),
        StructField("bwd_avg_bytes_bulk", StringType(), True),
        StructField("bwd_avg_packets_bulk", StringType(), True),
        StructField("bwd_avg_bulk_rate", StringType(), True),
        StructField("subflow_fwd_packets", StringType(), True),
        StructField("subflow_fwd_bytes", StringType(), True),
        StructField("subflow_bwd_packets", StringType(), True),
        StructField("subflow_bwd_bytes", StringType(), True),
        StructField("init_win_bytes_forward", StringType(), True),
        StructField("init_win_bytes_backward", StringType(), True),
        StructField("act_data_pkt_fwd", StringType(), True),
        StructField("min_seg_size_forward", StringType(), True),
        StructField("active_mean", StringType(), True),
        StructField("active_std", StringType(), True),
        StructField("active_max", StringType(), True),
        StructField("active_min", StringType(), True),
        StructField("idle_mean", StringType(), True),
        StructField("idle_std", StringType(), True),
        StructField("idle_max", StringType(), True),
        StructField("idle_min", StringType(), True),
        StructField("label", StringType(), True),
        StructField("partition_date", StringType(), True),
        StructField("produced_at_ts", LongType(), True)
    ])

    print(f"Connecting to Kafka at {kafka_servers}...")
    df = spark \
        .readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", kafka_servers) \
        .option("subscribe", topic_name) \
        .option("startingOffsets", "earliest") \
        .load()

    # Parse JSON from value column
    parsed_df = df.selectExpr("CAST(key AS STRING)", "CAST(value AS STRING)") \
        .select(from_json(col("value"), schema).alias("data")) \
        .select("data.*")
        
    # Add a processed_at timestamp
    normalized_df = parsed_df \
        .withColumn("processed_at", current_timestamp())

    checkpoint_location = "s3a://data/checkpoints/normalized-logs/"
    output_path = "s3a://data/normalized-logs/"

    print("Starting streaming query to write Parquet on S3...")
    query = normalized_df \
        .writeStream \
        .format("parquet") \
        .option("checkpointLocation", checkpoint_location) \
        .option("path", output_path) \
        .partitionBy("partition_date") \
        .trigger(processingTime="30 seconds") \
        .start()

    try:
        query.awaitTermination()
    except KeyboardInterrupt:
        print("Stopping streaming query...")
        query.stop()

if __name__ == "__main__":
    main()
