#!/usr/bin/env python3
import json
import ssl
import sys
import datetime
from datetime import timezone
import argparse
from opensearchpy import OpenSearch, helpers
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ocsf-uploader')

# Suppress insecure HTTPS warnings - only use in dev environments
urllib3.disable_warnings(InsecureRequestWarning)

def validate_timestamp(timestamp_str):
    """Validate and standardize timestamp format for OpenSearch compatibility"""
    try:
        # Check if timestamp lacks a T separator
        if ':' in timestamp_str and 'T' not in timestamp_str:
            # Format like "2023-07-25:52:08.000Z"
            parts = timestamp_str.split(':')
            if len(parts) >= 3:
                date_part = parts[0]
                time_part = ':'.join(parts[1:])
                timestamp_str = f"{date_part}T{time_part}"
        
        # Remove Z suffix if present and parse
        clean_ts = timestamp_str.replace('Z', '+00:00')
        dt = datetime.datetime.fromisoformat(clean_ts)
        
        # Format in the exact format expected by OpenSearch
        # yyyy-MM-dd'T'HH:mm:ss.SSSZ
        formatted_ts = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return formatted_ts
    except ValueError as e:
        logger.warning(f"Invalid timestamp format: {timestamp_str}, error: {e}")
        now = datetime.datetime.now(datetime.timezone.utc)
        return now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def map_to_ocsf(event):
    """Map generic log events to OCSF schema"""
    # Validate timestamps - but store for later use, don't modify the original event
    timestamp = None
    observed_timestamp = None
    
    if '@timestamp' in event:
        timestamp = validate_timestamp(event['@timestamp'])
    if 'observedTimestamp' in event:
        observed_timestamp = validate_timestamp(event['observedTimestamp'])
    
    # If no valid timestamp exists, use current time
    if not timestamp:
        now = datetime.datetime.now(timezone.utc)
        timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    
    # Convert timestamps to milliseconds since epoch for OpenSearch compatibility
    time_epoch_ms = int(datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp() * 1000)
    
    # Handle original_time in metadata
    if observed_timestamp:
        original_time_epoch_ms = int(datetime.datetime.fromisoformat(observed_timestamp.replace('Z', '+00:00')).timestamp() * 1000)
    else:
        original_time_epoch_ms = time_epoch_ms
    
    # Determine OCSF event type based on content
    if 'http' in event:
        # HTTP activity mapping
        ocsf_event = {
            "class_uid": 4002,  # HTTP Activity class ID
            "class_name": "HTTP Activity",
            "activity_id": 1,   # HTTP Request activity ID
            "activity_name": "HTTP Request",
            "severity_id": 1,   # Info severity
            "severity": "Informational",
            "status_id": 1,     # Success status by default
            "status": "Success",
            "time": time_epoch_ms,  # Use epoch milliseconds
            "metadata": {
                "product": {
                    "name": "Apache Web Server",
                    "vendor_name": "Apache",
                    "feature": {
                        "name": "Web Server Logs"
                    }
                },
                "version": "1.1.0",
                "profiles": ["http"],
                "original_time": original_time_epoch_ms  # Use epoch milliseconds here too
            },
            "observables": [],
            "src_endpoint": {
                "ip": event.get('communication', {}).get('source', {}).get('ip'),
                "location": {
                    "country": event.get('communication', {}).get('source', {}).get('geo', {}).get('country'),
                    "country_code": event.get('communication', {}).get('source', {}).get('geo', {}).get('country_iso_code')
                }
            },
            "http_request": {
                "method": event.get('http', {}).get('request', {}).get('method'),
                # Wrap URL in an object so it doesn't conflict with expected mapping
                "url": {
                    "full": event.get('http', {}).get('url')
                },
                "version": event.get('http', {}).get('flavor')
            },
            "http_response": {
                "status_code": event.get('http', {}).get('response', {}).get('status_code'),
                "size": event.get('http', {}).get('response', {}).get('bytes')
            },
            "user_agent": event.get('http', {}).get('user_agent', {}).get('original'),
            "unmapped": {
                "raw_data": event.get('body'),
                "trace_id": event.get('traceId'),
                "span_id": event.get('spanId')
            }
        }
        
        # Set status based on HTTP response code
        status_code = event.get('http', {}).get('response', {}).get('status_code')
        if status_code and status_code >= 400:
            ocsf_event['status_id'] = 2  # Failure
            ocsf_event['status'] = "Failure"
            
        return ocsf_event, "ocsf-1.1.0-4002-http_activity"
        
    elif event.get('event', {}).get('result') == 'error':
        # Error event mapping - more generic
        ocsf_event = {
            "class_uid": 6003,  # API Activity as fallback
            "class_name": "API Activity",
            "severity_id": 3,   # High severity for errors
            "severity": "High",
            "status_id": 2,     # Failure status
            "status": "Failure",
            "time": time_epoch_ms,  # Use epoch milliseconds
            "metadata": {
                "product": {
                    "name": "Apache Web Server",
                    "vendor_name": "Apache",
                    "feature": {
                        "name": "Web Server Logs"
                    }
                },
                "version": "1.1.0",
                # Convert observedTimestamp to epoch ms
                "original_time": original_time_epoch_ms
            },
            "message": event.get('body'),
            "src_endpoint": {
                "ip": event.get('communication', {}).get('source', {}).get('ip'),
                "location": {
                    "country": event.get('communication', {}).get('source', {}).get('geo', {}).get('country'),
                    "country_code": event.get('communication', {}).get('source', {}).get('geo', {}).get('country_iso_code')
                }
            },
            "unmapped": {
                "raw_data": event.get('body'),
                "trace_id": event.get('traceId'),
                "span_id": event.get('spanId'),
                "severity_text": event.get('severity', {}).get('text')
            }
        }
        return ocsf_event, "ocsf-1.1.0-6003-api_activity"
    
    # Default fallback to network activity
    ocsf_event = {
        "class_uid": 4001,  # Network Activity
        "class_name": "Network Activity",
        "time": time_epoch_ms,  # Use epoch milliseconds
        "metadata": {
            "product": {
                "name": "Apache Web Server",
                "vendor_name": "Apache"
            },
            "version": "1.1.0",
            "original_time": original_time_epoch_ms
        },
        "unmapped": event  # Store entire original event
    }
    return ocsf_event, "ocsf-1.1.0-4001-network_activity"

def upload_to_opensearch(client, events, batch_size=100):
    """Upload events to OpenSearch in batches"""
    successful = 0
    failed = 0
    
    # Group events by index
    grouped_events = {}
    for event in events:
        ocsf_event, index_name = map_to_ocsf(event)
        if index_name not in grouped_events:
            grouped_events[index_name] = []
        grouped_events[index_name].append(ocsf_event)
    
    # Process each index group
    for index_name, index_events in grouped_events.items():
        # Process in batches
        for i in range(0, len(index_events), batch_size):
            batch = index_events[i:i+batch_size]
            bulk_actions = []
            
            for event in batch:
                action = {
                    "_index": index_name,
                    "_source": event
                }
                bulk_actions.append(action)
            
            try:
                success, failed_items = helpers.bulk(client, bulk_actions, stats_only=False, raise_on_error=False)
                successful += success
                
                # Count and log failed items
                if len(failed_items) > 0:
                    for item in failed_items:
                        logger.error(f"Failed to index document: {item}")
                    failed += len(failed_items)
                    
            except Exception as e:
                logger.error(f"Bulk upload error: {str(e)}")
                failed += len(batch)
    
    return successful, failed

def main():
    parser = argparse.ArgumentParser(description='Upload data to OpenSearch using OCSF schema')
    parser.add_argument('--host', default='15.206.174.96', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--input', required=True, help='Input JSON file path')
    parser.add_argument('--secure', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for bulk operations')
    
    args = parser.parse_args()
    
    # Configure SSL context
    ssl_context = ssl.create_default_context()
    if not args.secure:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        logger.warning("SSL certificate verification disabled - not recommended for production")
    
    # OpenSearch client configuration
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        ssl_context=ssl_context,
        timeout=30
    )
    
    # Verify connection
    try:
        info = client.info()
        logger.info(f"Connected to OpenSearch cluster: {info['cluster_name']}, version: {info['version']['number']}")
    except Exception as e:
        logger.error(f"Failed to connect to OpenSearch: {str(e)}")
        sys.exit(1)
    
    # Read and parse input file
    try:
        with open(args.input, 'r') as f:
            events = json.load(f)
            logger.info(f"Loaded {len(events)} events from {args.input}")
    except Exception as e:
        logger.error(f"Failed to load input file: {str(e)}")
        sys.exit(1)
    
    # Upload data
    successful, failed = upload_to_opensearch(client, events, args.batch_size)
    logger.info(f"Upload complete: {successful} documents indexed successfully, {failed} failed")

if __name__ == "__main__":
    main()
