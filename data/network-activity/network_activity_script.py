#!/usr/bin/env python3
import requests
import json
import time
import hashlib
import argparse
import os
import re
import logging
from datetime import datetime, timezone
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
from urllib3.exceptions import InsecureRequestWarning
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_activity_ingest.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("network_activity_ingest")

# Configuration constants
DEFAULT_OPENSEARCH_HOST = "localhost"
DEFAULT_OPENSEARCH_PORT = 9200
DEFAULT_OPENSEARCH_USER = "admin"
DEFAULT_OPENSEARCH_PASS = "Anubhav@321"
DEFAULT_OCSF_URL = "https://schema.ocsf.io/sample/1.1.0/classes/network_activity?profiles="
DEFAULT_INDEX = "ocsf-1.1.0-4001-network_activity"
DEFAULT_BATCH_SIZE = 10
DEFAULT_SAMPLES_COUNT = 100 
DEFAULT_DELAY = 0.5  # seconds between API calls

def create_opensearch_client(host, port, username, password, use_ssl=True, verify_certs=False, retry_count=3, file_only_mode=False):
    if file_only_mode:
        logger.info("Running in file-only mode. No OpenSearch connection will be established.")
        return None
    connection_params = {
        'hosts': [{'host': host, 'port': port}],
        'http_auth': (username, password),
        'use_ssl': use_ssl,
        'verify_certs': verify_certs,
        'ssl_show_warn': False,
        'connection_class': RequestsHttpConnection,
        'timeout': 30,
        'retry_on_timeout': True,
        'max_retries': retry_count
    }
    for attempt in range(retry_count):
        try:
            client = OpenSearch(**connection_params)
            info = client.info()
            logger.info(f"Connected to {info['version']['distribution']} {info['version']['number']}")
            return client
        except Exception as e:
            if attempt < retry_count - 1:
                wait_time = 2 ** attempt
                logger.warning(f"Connection attempt {attempt+1}/{retry_count} failed. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Failed to connect to OpenSearch after {retry_count} attempts: {e}")
                raise

def delete_index_if_exists(client, index_name):
    if client.indices.exists(index=index_name):
        try:
            client.indices.delete(index=index_name)
            logger.info(f"Deleted existing index: {index_name}")
        except Exception as e:
            logger.error(f"Error deleting index {index_name}: {e}")
            raise

def create_index_with_mappings(client, index_name):
    if client.indices.exists(index=index_name):
        logger.info(f"Index {index_name} already exists.")
        return True
    mappings = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "observedTimestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "start_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "end_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "create_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "update_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "detect_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "first_seen": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "last_seen": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                "metadata": {
                    "type": "object",
                    "properties": {
                        "original_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                        "logged_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                        "processed_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                        "modified_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"}
                    }
                },
                "tls": {
                    "type": "object",
                    "properties": {
                        "certificate": {
                            "type": "object",
                            "properties": {
                                "created_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"},
                                "expiration_time": {"type": "date", "format": "strict_date_optional_time||epoch_millis||yyyy-MM-dd'T'HH:mm:ss.SSSZ"}
                            }
                        }
                    }
                }
            }
        },
        "settings": {
            "index.mapping.ignore_malformed": True,
            "number_of_shards": 1,
            "number_of_replicas": 1
        }
    }
    try:
        client.indices.create(index=index_name, body=mappings)
        logger.info(f"Created index {index_name} with updated mappings.")
        return True
    except Exception as e:
        logger.error(f"Error creating index {index_name}: {e}")
        return False

def fetch_network_activity(url, retry_count=3, retry_delay=1):
    for attempt in range(retry_count):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if attempt < retry_count - 1:
                wait_time = retry_delay * (2 ** attempt)
                logger.warning(f"Request attempt {attempt+1}/{retry_count} failed. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Error fetching data from {url}: {e}")
                return None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from {url}: {e}")
            return None

def normalize_time_format(timestamp):
    if timestamp is None:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    if isinstance(timestamp, (int, float)):
        try:
            if timestamp > 1_000_000_000_000:
                timestamp = timestamp / 1000
            dt = datetime.fromtimestamp(timestamp, timezone.utc)
            return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        except Exception as e:
            logger.warning(f"Failed to convert epoch timestamp {timestamp}: {e}")
            return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    if not isinstance(timestamp, str):
        try:
            timestamp = str(timestamp)
        except Exception:
            return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$', timestamp):
        return timestamp
    try:
        if '+00:00' in timestamp:
            dt = datetime.fromisoformat(timestamp)
        else:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    except Exception:
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def normalize_network_activity(data):
    normalized = {}
    if isinstance(data, dict):
        normalized.update(data)
    else:
        logger.error(f"Unexpected data format: {type(data)}")
        return None

    if 'time' in normalized:
        normalized.pop('time')

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    normalized.setdefault('@timestamp', timestamp)
    normalized.setdefault('observedTimestamp', normalized.get('@timestamp'))

    for field in ['@timestamp', 'observedTimestamp']:
        normalized[field] = normalize_time_format(normalized[field])
        
    if 'metadata' in normalized and isinstance(normalized['metadata'], dict):
        for field in ['original_time', 'logged_time', 'processed_time', 'modified_time', 'creation_time', 'update_time', 'ingestion_time']:
            if field in normalized['metadata']:
                normalized['metadata'][field] = normalize_time_format(normalized['metadata'][field])
    
    for field in ['start_time', 'end_time', 'create_time', 'update_time', 'detect_time', 'first_seen', 'last_seen']:
        if field in normalized:
            normalized[field] = normalize_time_format(normalized[field])
    
    if 'tls' in normalized and isinstance(normalized['tls'], dict) and 'certificate' in normalized['tls']:
        for field in ['created_time', 'expiration_time']:
            if field in normalized['tls']['certificate']:
                normalized['tls']['certificate'][field] = normalize_time_format(normalized['tls']['certificate'][field])
    
    normalized.setdefault('activity_id', 4001)
    normalized.setdefault('activity_name', 'Network Activity')
    normalized.setdefault('class_uid', '4001')
    normalized.setdefault('class_name', 'Network Activity')
    
    if 'traceId' not in normalized:
        normalized['traceId'] = hashlib.md5(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    if 'spanId' not in normalized:
        normalized['spanId'] = normalized['traceId'][:16]
    
    return normalized

def save_to_file(data, output_dir, batch_num, index_num):
    try:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = os.path.join(output_dir, f"network_activity_batch{batch_num}_doc{index_num}_{timestamp}.json")
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving document to file: {e}")
        return False

def upload_bulk(client, bulk_data):
    try:
        success, errors = helpers.bulk(client, bulk_data, stats_only=True)
        if errors:
            logger.warning(f"Encountered {errors} errors during bulk upload")
        return success, errors
    except Exception as e:
        logger.error(f"Bulk upload failed: {e}")
        return 0, len(bulk_data)

def process_and_upload_batch(client, normalized_data_list, index, output_dir=None, batch_num=0):
    success_count = 0
    error_count = 0
    bulk_data = []
    file_save_results = []
    for i, data in enumerate(normalized_data_list):
        if output_dir:
            file_saved = save_to_file(data, output_dir, batch_num, i)
            file_save_results.append(file_saved)
        doc_str = json.dumps(data, sort_keys=True)
        doc_id = hashlib.md5(doc_str.encode()).hexdigest()
        bulk_data.append({
            '_index': index,
            '_id': doc_id,
            '_source': data
        })
    if bulk_data and client is not None:
        succ, errs = upload_bulk(client, bulk_data)
        success_count += succ
        error_count += errs
    elif output_dir:
        success_count = sum(1 for result in file_save_results if result)
        error_count = len(file_save_results) - success_count
    return success_count, error_count

def fetch_and_index_batch(client, ocsf_url, index, batch_size, delay, output_dir=None, batch_num=0):
    normalized_data_list = []
    fetch_errors = 0
    for i in range(batch_size):
        raw_data = fetch_network_activity(ocsf_url)
        if raw_data:
            normalized_data = normalize_network_activity(raw_data)
            if normalized_data:
                normalized_data_list.append(normalized_data)
            else:
                fetch_errors += 1
        else:
            fetch_errors += 1
        if i < batch_size - 1:
            time.sleep(delay)
    if normalized_data_list:
        success_count, error_count = process_and_upload_batch(
            client, normalized_data_list, index, output_dir, batch_num
        )
        return success_count, error_count + fetch_errors
    else:
        return 0, fetch_errors

def upload_from_directory(client, input_dir, index):
    logger.info(f"Uploading files from {input_dir}")
    json_files = sorted([os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith('.json')])
    if not json_files:
        logger.warning(f"No JSON files found in {input_dir}")
        return 0, 0
    logger.info(f"Found {len(json_files)} JSON files to process")
    success_count = 0
    error_count = 0
    bulk_data = []
    bulk_size = 50
    for i, file_path in enumerate(json_files):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            normalized_data = normalize_network_activity(data)
            if normalized_data:
                doc_str = json.dumps(normalized_data, sort_keys=True)
                doc_id = hashlib.md5(doc_str.encode()).hexdigest()
                bulk_data.append({
                    '_index': index,
                    '_id': doc_id,
                    '_source': normalized_data
                })
                if len(bulk_data) >= bulk_size:
                    succ, errs = upload_bulk(client, bulk_data)
                    success_count += succ
                    error_count += errs
                    bulk_data = []
                    logger.info(f"Processed {i+1}/{len(json_files)} files - Current success rate: {success_count/(success_count+error_count or 1)*100:.1f}%")
            else:
                logger.warning(f"Could not normalize data from {file_path}")
                error_count += 1
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            error_count += 1
    if bulk_data:
        succ, errs = upload_bulk(client, bulk_data)
        success_count += succ
        error_count += errs
    return success_count, error_count

def main():
    parser = argparse.ArgumentParser(description='Ingest OCSF network activity data into OpenSearch')
    parser.add_argument('--host', default=DEFAULT_OPENSEARCH_HOST, help='OpenSearch host')
    parser.add_argument('--port', type=int, default=DEFAULT_OPENSEARCH_PORT, help='OpenSearch port')
    parser.add_argument('--user', default=DEFAULT_OPENSEARCH_USER, help='OpenSearch username')
    parser.add_argument('--password', default=DEFAULT_OPENSEARCH_PASS, help='OpenSearch password')
    parser.add_argument('--ssl', action='store_true', help='Use SSL for OpenSearch connection')
    parser.add_argument('--verify-certs', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--url', default=DEFAULT_OCSF_URL, help='OCSF schema API URL')
    parser.add_argument('--index', default=DEFAULT_INDEX, help='OpenSearch index to write to')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE, help='Documents per batch')
    parser.add_argument('--count', type=int, default=DEFAULT_SAMPLES_COUNT, help='Total number of samples to ingest')
    parser.add_argument('--delay', type=float, default=DEFAULT_DELAY, help='Delay between API requests (seconds)')
    parser.add_argument('--continuous', action='store_true', help='Run continuously, ignoring --count')
    parser.add_argument('--output-dir', help='Directory to save JSON files (if set, documents are saved to file)')
    parser.add_argument('--file-only', action='store_true', help='Only save to files, do not connect to OpenSearch')
    parser.add_argument('--retry-count', type=int, default=3, help='Number of connection retry attempts')
    parser.add_argument('--input-dir', help='Upload existing JSON files from directory')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set logging level')
    parser.add_argument('--create-index', action='store_true', help='Create index with custom mappings if it doesn\'t exist')
    parser.add_argument('--recreate-index', action='store_true', help='Delete and recreate index (use with caution)')
    args = parser.parse_args()
    logger.setLevel(getattr(logging, args.log_level))
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
    logger.info("=== Starting OCSF Network Activity Ingestion ===")
    if not args.file_only:
        logger.info(f"Target OpenSearch: {args.host}:{args.port}")
    if args.output_dir:
        logger.info(f"Output directory: {args.output_dir}")
    if args.input_dir:
        logger.info(f"Input directory: {args.input_dir}")
    else:
        logger.info(f"Source OCSF API: {args.url}")
    logger.info(f"Target index: {args.index}")

    client = None
    try:
        if not args.file_only:
            client = create_opensearch_client(
                args.host, args.port, args.user, args.password,
                use_ssl=args.ssl, verify_certs=args.verify_certs,
                retry_count=args.retry_count, file_only_mode=args.file_only
            )
            if client and args.create_index:
                if args.recreate_index:
                    delete_index_if_exists(client, args.index)
                if not create_index_with_mappings(client, args.index):
                    if not args.output_dir:
                        logger.error("Failed to create index and no output directory specified. Exiting.")
                        return
                    logger.warning("Continuing in file-only mode due to index creation failure")
                    client = None
                    args.file_only = True
    except Exception as e:
        if not args.output_dir and not args.input_dir:
            logger.error("Failed to connect to OpenSearch and no output/input directory specified. Exiting.")
            return
        logger.warning(f"Continuing in file-only mode due to connection error: {e}")
        client = None
        args.file_only = True

    if args.input_dir:
        if client:
            succ, errs = upload_from_directory(client, args.input_dir, args.index)
            logger.info("=== Upload from directory complete ===")
            logger.info(f"Total successful: {succ}")
            logger.info(f"Total errors: {errs}")
        else:
            logger.error("Cannot upload from directory without OpenSearch connection")
        return

    total_success = 0
    total_error = 0
    batches = 0

    try:
        if args.continuous:
            logger.info("Running in continuous mode. Press Ctrl+C to stop.")
            while True:
                succ, err = fetch_and_index_batch(
                    client, args.url, args.index, args.batch_size, args.delay,
                    output_dir=args.output_dir, batch_num=batches+1
                )
                batches += 1
                total_success += succ
                total_error += err
                logger.info(f"Batch {batches} completed - Success: {succ}, Errors: {err}, Total indexed: {total_success}")
        else:
            remaining = args.count
            while remaining > 0:
                current_batch = min(remaining, args.batch_size)
                succ, err = fetch_and_index_batch(
                    client, args.url, args.index, current_batch, args.delay,
                    output_dir=args.output_dir, batch_num=batches+1
                )
                batches += 1
                total_success += succ
                total_error += err
                remaining -= current_batch
                logger.info(f"Batch {batches} completed - Success: {succ}, Errors: {err}, Total indexed: {total_success}, Remaining: {remaining}")
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
    finally:
        logger.info("=== OCSF Network Activity Ingestion Complete ===")
        logger.info(f"Total batches: {batches}")
        logger.info(f"Total success: {total_success}")
        logger.info(f"Total errors: {total_error}")
        if args.output_dir:
            logger.info(f"Output saved to: {args.output_dir}")

if __name__ == "__main__":
    main()
