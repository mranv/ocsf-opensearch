#!/usr/bin/env python3
import re
import json
import ssl
import sys
import os
import datetime
from datetime import timezone
import argparse
from opensearchpy import OpenSearch, helpers
import urllib3
import logging
from urllib3.exceptions import InsecureRequestWarning
import time
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ocsf-network-uploader')

def get_credentials():
    """Retrieve credentials from environment variables"""
    username = os.environ.get('OPENSEARCH_USER')
    password = os.environ.get('OPENSEARCH_PASSWORD')
    
    if not username or not password:
        logger.error("Missing credentials. Set OPENSEARCH_USER and OPENSEARCH_PASSWORD environment variables.")
        sys.exit(1)
        
    return username, password

def parse_apache_log_line(line, timeout=1.0):
    """
    Parse a single Apache Combined Log Format line with timeout protection.
    """
    pattern = (
        r'^(?P<ip>\S+)\s+'                        # IP
        r'\S+\s+\S+\s+'                           # ignore ident and userid
        r'\[(?P<timestamp>[^\]]+)\]\s+'           # timestamp in []
        r'"(?P<request>[^"]*)"\s+'                # request line
        r'(?P<status>\d{3})\s+'                   # status code
        r'(?P<bytes>\S+)\s+'                      # response size
        r'"(?P<referrer>[^"]*)"\s+'               # referrer
        r'"(?P<user_agent>[^"]*)"'                # user agent
    )
    
    # Set a timeout for regex matching to prevent ReDoS attacks
    start_time = time.time()
    match = None
    
    try:
        match = re.match(pattern, line)
        if time.time() - start_time > timeout:
            logger.warning(f"Regex matching timeout exceeded: {timeout}s")
            return None
    except Exception as e:
        logger.warning(f"Error parsing log line: {str(e)}")
        return None
        
    if match:
        return match.groupdict()
    else:
        return None

def validate_and_sanitize_fields(fields):
    """Validate and sanitize parsed fields to prevent injection attacks"""
    if not fields:
        return None
        
    # Validate IP format
    ip = fields.get('ip', '')
    if not re.match(r'^[\d\.]+$', ip):
        fields['ip'] = '0.0.0.0'  # Sanitize invalid IP
    
    # Sanitize request fields for potential command injection
    request = fields.get('request', '')
    if ';' in request or '|' in request or '>' in request:
        fields['request'] = 'INVALID_REQUEST'
        
    # Validate status code is numeric
    status = fields.get('status', '')
    if not status.isdigit():
        fields['status'] = '0'
        
    # Validate bytes is numeric or '-'
    bytes_value = fields.get('bytes', '')
    if not (bytes_value.isdigit() or bytes_value == '-'):
        fields['bytes'] = '0'
        
    return fields

def map_to_ocsf_network_activity(log_fields):
    """
    Map parsed Apache log fields to an OCSF Network Activity event.
    
    This function maps Apache log fields to the OCSF 1.1.0 Network Activity (class_uid 4001) schema.
    """
    # Parse Apache timestamp, e.g. "17/May/2015:10:05:03 +0000"
    timestamp_str = log_fields.get('timestamp')
    try:
        dt = datetime.datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        epoch_ms = int(dt.timestamp() * 1000)
    except Exception as e:
        logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
        dt = datetime.datetime.now(timezone.utc)
        epoch_ms = int(dt.timestamp() * 1000)
    
    # Split the request line into method, URL, and HTTP version
    request_line = log_fields.get('request', '')
    parts = request_line.split()
    if len(parts) == 3:
        method, url_string, version = parts
    else:
        method, url_string, version = "", "", ""
    
    try:
        status_code = int(log_fields.get('status', 0))
    except ValueError:
        status_code = 0
        
    # If response size is "-" or non-numeric, default to 0
    size_str = log_fields.get('bytes', '0')
    size = int(size_str) if size_str.isdigit() else 0

    # Parse URL components
    url_components = {}
    if url_string and url_string != "":
        if "://" in url_string:
            scheme, rest = url_string.split("://", 1)
            url_components["scheme"] = scheme
        else:
            scheme = "http"
            rest = url_string
            url_components["scheme"] = scheme
            
        if "/" in rest:
            hostname, path = rest.split("/", 1)
            path = "/" + path
        else:
            hostname = rest
            path = "/"
            
        url_components["hostname"] = hostname
        url_components["path"] = path
        
        if "?" in path:
            path, query = path.split("?", 1)
            url_components["path"] = path
            url_components["query_string"] = query
            
        if ":" in hostname:
            hostname, port_str = hostname.split(":", 1)
            try:
                url_components["port"] = int(port_str)
            except ValueError:
                pass
            url_components["hostname"] = hostname

    # Determine status 
    if 200 <= status_code < 400:
        status = "Success"
        status_id = 1
    else:
        status = "Failure"
        status_id = 2

    # Determine severity based on status code
    if status_code >= 500:
        severity = "Error"
        severity_id = 3
    elif status_code >= 400:
        severity = "Warning"
        severity_id = 2
    else:
        severity = "Informational"
        severity_id = 1

    # Format date time according to OCSF schema requirements
    # OpenSearch expects format: yyyy-MM-dd'T'HH:mm:ss.SSSZ
    time_dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + dt.strftime('%z')
    
    # Build the OCSF Network Activity event
    event = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "category_uid": 4,
        "category_name": "Network Activity",
        "activity_id": 1,  # HTTP activity
        "activity_name": "HTTP Request",
        "type_uid": 400101,  # HTTP Request
        "type_name": "HTTP Request",
        "severity_id": severity_id,
        "severity": severity,
        "status_id": status_id,
        "status": status,
        "time": epoch_ms,
        "time_dt": time_dt,  # Updated format without colon in timezone
        "metadata": {
            "version": "1.1.0",
            "uid": str(uuid.uuid4())
        },
        "connection_info": {
            "direction": "Inbound",
            "direction_id": 1,
            "protocol_name": "HTTP",
            "protocol_ver": version,
            "uid": str(uuid.uuid4())
        },
        "src_endpoint": {
            "ip": log_fields.get('ip'),
            "user_agent": log_fields.get('user_agent')
        },
        "dst_endpoint": {
            "port": 80  # Default HTTP port
        },
        "url": url_components,
        "proxy_http_request": {
            "http_method": method,
            "referrer": log_fields.get('referrer'),
            "user_agent": log_fields.get('user_agent'),
            "url": url_components
        },
        "proxy_http_response": {
            "code": status_code,
            "length": size,
            "status": status
        },
        "traffic": {
            "bytes_in": 0,  # Unknown from log
            "bytes_out": size
        }
    }
    
    # Create an index name based on event date, e.g. "ocsf-1.1.0-4001-network_activity-2015.05.17-000000"
    index_name = f"ocsf-1.1.0-4001-network_activity-{dt.strftime('%Y.%m.%d')}-000000"
    return event, index_name

def upload_to_opensearch_ocsf(client, raw_log_lines, batch_size=100, max_retries=3):
    """Parse raw log lines, map them to OCSF Network Activity events, and upload them in batches."""
    events = []
    failed_lines = 0
    
    for line in raw_log_lines:
        line = line.strip()
        if not line:
            continue
            
        # Parse with timeout protection
        parsed = parse_apache_log_line(line)
        
        if not parsed:
            logger.warning(f"Failed to parse line: {line[:50]}...")  # Log only first 50 chars
            failed_lines += 1
            continue
            
        # Validate and sanitize fields
        validated_fields = validate_and_sanitize_fields(parsed)
        if not validated_fields:
            failed_lines += 1
            continue
            
        event, index_name = map_to_ocsf_network_activity(validated_fields)
        # Attach the index name to the event for grouping later
        events.append((event, index_name))
    
    # Group events by index
    grouped_events = {}
    for event, index_name in events:
        if index_name not in grouped_events:
            grouped_events[index_name] = []
        grouped_events[index_name].append(event)
    
    successful = 0
    failed = 0
    
    # Rate limiting for failed uploads
    consecutive_failures = 0
    backoff_time = 1  # Initial backoff time in seconds
    
    for index_name, index_events in grouped_events.items():
        # Process in smaller batches
        for i in range(0, len(index_events), batch_size):
            batch_events = index_events[i:i+batch_size]
            bulk_actions = []
            
            for event in batch_events:
                action = {
                    "_index": index_name,
                    "_source": event
                }
                bulk_actions.append(action)
                
            # Implement retry with exponential backoff
            retries = 0
            while retries < max_retries:
                try:
                    if consecutive_failures >= 5:
                        # If we've had multiple consecutive failures, implement backoff
                        logger.warning(f"Too many consecutive failures, backing off for {backoff_time}s")
                        time.sleep(backoff_time)
                        backoff_time *= 2  # Exponential backoff
                        
                    success, failed_items = helpers.bulk(
                        client, 
                        bulk_actions, 
                        stats_only=False, 
                        raise_on_error=False,
                        request_timeout=30  # Add timeout
                    )
                    
                    successful += success
                    consecutive_failures = 0
                    backoff_time = 1  # Reset backoff time
                    
                    if failed_items:
                        for item in failed_items:
                            error_type = item.get('index', {}).get('error', {}).get('type', 'unknown')
                            error_reason = item.get('index', {}).get('error', {}).get('reason', 'unknown')
                            logger.error(f"Failed to index document: {error_type} - {error_reason}")
                        failed += len(failed_items)
                    break  # Success, exit retry loop
                    
                except Exception as e:
                    retries += 1
                    consecutive_failures += 1
                    logger.error(f"Bulk upload error (attempt {retries}/{max_retries}): {str(e)}")
                    if retries >= max_retries:
                        failed += len(bulk_actions)
                    time.sleep(retries * 2)  # Progressive retry delay
    
    return successful, failed, failed_lines

def create_secure_client(args):
    """Create a properly secured OpenSearch client"""
    username, password = get_credentials()
    
    # Configure SSL context for OpenSearch
    ssl_context = ssl.create_default_context()
    
    # SSL verification control - always disable for self-signed certificates
    if args.insecure:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        logger.warning("SSL verification disabled - using insecure connection")
        # Suppress warning messages
        urllib3.disable_warnings(InsecureRequestWarning)
    
    return OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(username, password),
        use_ssl=True,
        ssl_context=ssl_context,
        timeout=30,
        retry_on_timeout=True,
        max_retries=3
    )

def validate_input_file(file_path, max_size_mb=100):
    """Validate the input file exists and is within size limits"""
    if not os.path.exists(file_path):
        logger.error(f"Input file does not exist: {file_path}")
        return False
        
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if file_size_mb > max_size_mb:
        logger.error(f"Input file exceeds maximum size: {file_size_mb:.2f}MB > {max_size_mb}MB")
        return False
        
    return True

def main():
    parser = argparse.ArgumentParser(description='Parse Apache logs and upload OCSF Network Activity events to OpenSearch')
    parser.add_argument('--host', required=True, help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--input', required=True, help='Input raw log file path')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (for self-signed certificates)')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for bulk operations')
    parser.add_argument('--max-size', type=int, default=100, help='Maximum log file size in MB')
    
    args = parser.parse_args()
    
    # Validate input file
    if not validate_input_file(args.input, args.max_size):
        sys.exit(1)
    
    # Create client
    client = create_secure_client(args)
    
    # Verify connection
    try:
        info = client.info()
        logger.info(f"Connected to OpenSearch cluster: {info['cluster_name']}, version: {info['version']['number']}")
    except Exception as e:
        logger.error(f"Failed to connect to OpenSearch: {str(e)}")
        logger.error("If using a self-signed certificate, try adding the --insecure flag")
        sys.exit(1)
    
    # Read log file
    try:
        with open(args.input, 'r', encoding='utf-8', errors='replace') as f:
            raw_lines = f.readlines()
            logger.info(f"Loaded {len(raw_lines)} lines from {args.input}")
    except Exception as e:
        logger.error(f"Failed to load input file: {str(e)}")
        sys.exit(1)
    
    # Parse logs and upload to OpenSearch
    successful, failed, failed_lines = upload_to_opensearch_ocsf(client, raw_lines, args.batch_size)
    
    logger.info(f"Upload complete: {successful} documents indexed successfully, {failed} failed to index")
    logger.info(f"Parse failures: {failed_lines} lines could not be parsed")
    
    # Exit with non-zero code if there were failures
    if failed > 0 or failed_lines > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()