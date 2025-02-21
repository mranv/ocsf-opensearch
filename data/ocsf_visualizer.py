#!/usr/bin/env python3
import json
import argparse
import ssl
import sys
import os
import uuid
from opensearchpy import OpenSearch
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ocsf-visualizer')

def get_credentials():
    """Retrieve credentials from environment variables"""
    username = os.environ.get('OPENSEARCH_USER')
    password = os.environ.get('OPENSEARCH_PASSWORD')
    
    if not username or not password:
        logger.error("Missing credentials. Set OPENSEARCH_USER and OPENSEARCH_PASSWORD environment variables.")
        sys.exit(1)
        
    return username, password

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

def generate_visualizations(index_pattern):
    """Generate visualization objects in NDJSON format for Kibana/OpenSearch Dashboards"""
    
    # Create a unique dashboard ID
    dashboard_id = f"ocsf-network-activity-dashboard-{uuid.uuid4().hex[:8]}"
    
    visualizations = []
    
    # 1. Index Pattern Definition
    index_pattern_object = {
        "_id": f"index-pattern:{index_pattern}",
        "_type": "doc",
        "_source": {
            "index-pattern": {
                "title": index_pattern,
                "timeFieldName": "time_dt"
            },
            "type": "index-pattern"
        }
    }
    visualizations.append(index_pattern_object)
    
    # 2. HTTP Status Code Distribution (Pie Chart)
    status_viz_id = f"viz-http-status-{uuid.uuid4().hex[:8]}"
    status_visualization = {
        "_id": f"visualization:{status_viz_id}",
        "_type": "doc",
        "_source": {
            "visualization": {
                "title": "HTTP Status Code Distribution",
                "visState": json.dumps({
                    "title": "HTTP Status Code Distribution",
                    "type": "pie",
                    "params": {
                        "type": "pie",
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right"
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "terms",
                            "schema": "segment",
                            "params": {
                                "field": "proxy_http_response.code",
                                "size": 10,
                                "order": "desc",
                                "orderBy": "1"
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Distribution of HTTP status codes",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,
                        "filter": [],
                        "query": {"query": "", "language": "lucene"}
                    })
                }
            },
            "type": "visualization"
        }
    }
    visualizations.append(status_visualization)
    
    # 3. Top User Agents (Bar Chart)
    agents_viz_id = f"viz-user-agents-{uuid.uuid4().hex[:8]}"
    agents_visualization = {
        "_id": f"visualization:{agents_viz_id}",
        "_type": "doc",
        "_source": {
            "visualization": {
                "title": "Top User Agents",
                "visState": json.dumps({
                    "title": "Top User Agents",
                    "type": "histogram",
                    "params": {
                        "type": "histogram",
                        "grid": {
                            "categoryLines": False
                        },
                        "categoryAxes": [
                            {
                                "id": "CategoryAxis-1",
                                "type": "category",
                                "position": "bottom",
                                "show": True,
                                "style": {},
                                "scale": {
                                    "type": "linear"
                                },
                                "labels": {
                                    "show": True,
                                    "truncate": 100
                                },
                                "title": {}
                            }
                        ],
                        "valueAxes": [
                            {
                                "id": "ValueAxis-1",
                                "name": "LeftAxis-1",
                                "type": "value",
                                "position": "left",
                                "show": True,
                                "style": {},
                                "scale": {
                                    "type": "linear",
                                    "mode": "normal"
                                },
                                "labels": {
                                    "show": True,
                                    "rotate": 0,
                                    "filter": False,
                                    "truncate": 100
                                },
                                "title": {
                                    "text": "Count"
                                }
                            }
                        ]
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "terms",
                            "schema": "segment",
                            "params": {
                                "field": "src_endpoint.user_agent.keyword",
                                "size": 10,
                                "order": "desc",
                                "orderBy": "1"
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Top 10 user agents by request count",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,
                        "filter": [],
                        "query": {"query": "", "language": "lucene"}
                    })
                }
            },
            "type": "visualization"
        }
    }
    visualizations.append(agents_visualization)
    
    # 4. Traffic Over Time (Line Chart)
    traffic_viz_id = f"viz-traffic-time-{uuid.uuid4().hex[:8]}"
    traffic_visualization = {
        "_id": f"visualization:{traffic_viz_id}",
        "_type": "doc",
        "_source": {
            "visualization": {
                "title": "Traffic Over Time",
                "visState": json.dumps({
                    "title": "Traffic Over Time",
                    "type": "line",
                    "params": {
                        "type": "line",
                        "grid": {
                            "categoryLines": False
                        },
                        "categoryAxes": [
                            {
                                "id": "CategoryAxis-1",
                                "type": "category",
                                "position": "bottom",
                                "show": True,
                                "style": {},
                                "scale": {
                                    "type": "linear"
                                },
                                "labels": {
                                    "show": True,
                                    "truncate": 100
                                },
                                "title": {}
                            }
                        ],
                        "valueAxes": [
                            {
                                "id": "ValueAxis-1",
                                "name": "LeftAxis-1",
                                "type": "value",
                                "position": "left",
                                "show": True,
                                "style": {},
                                "scale": {
                                    "type": "linear",
                                    "mode": "normal"
                                },
                                "labels": {
                                    "show": True,
                                    "rotate": 0,
                                    "filter": False,
                                    "truncate": 100
                                },
                                "title": {
                                    "text": "Count"
                                }
                            }
                        ],
                        "seriesParams": [
                            {
                                "show": "true",
                                "type": "line",
                                "mode": "normal",
                                "data": {
                                    "label": "Count",
                                    "id": "1"
                                },
                                "valueAxis": "ValueAxis-1",
                                "drawLinesBetweenPoints": True,
                                "showCircles": True
                            }
                        ],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "times": [],
                        "addTimeMarker": False
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "date_histogram",
                            "schema": "segment",
                            "params": {
                                "field": "time_dt",
                                "interval": "auto",
                                "customInterval": "2h",
                                "min_doc_count": 1,
                                "extended_bounds": {}
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Network traffic over time",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,
                        "filter": [],
                        "query": {"query": "", "language": "lucene"}
                    })
                }
            },
            "type": "visualization"
        }
    }
    visualizations.append(traffic_visualization)
    
    # 5. Top Source IPs (Data Table)
    ips_viz_id = f"viz-source-ips-{uuid.uuid4().hex[:8]}"
    ips_visualization = {
        "_id": f"visualization:{ips_viz_id}",
        "_type": "doc",
        "_source": {
            "visualization": {
                "title": "Top Source IPs",
                "visState": json.dumps({
                    "title": "Top Source IPs",
                    "type": "table",
                    "params": {
                        "perPage": 10,
                        "showPartialRows": False,
                        "showMetricsAtAllLevels": False,
                        "sort": {
                            "columnIndex": None,
                            "direction": None
                        },
                        "showTotal": False,
                        "totalFunc": "sum"
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "terms",
                            "schema": "bucket",
                            "params": {
                                "field": "src_endpoint.ip",
                                "size": 20,
                                "order": "desc",
                                "orderBy": "1"
                            }
                        }
                    ]
                }),
                "uiStateJSON": json.dumps({
                    "vis": {
                        "params": {
                            "sort": {
                                "columnIndex": None,
                                "direction": None
                            }
                        }
                    }
                }),
                "description": "Top 20 source IP addresses by request count",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,
                        "filter": [],
                        "query": {"query": "", "language": "lucene"}
                    })
                }
            },
            "type": "visualization"
        }
    }
    visualizations.append(ips_visualization)
    
    # 6. HTTP Methods Distribution (Pie Chart)
    methods_viz_id = f"viz-http-methods-{uuid.uuid4().hex[:8]}"
    methods_visualization = {
        "_id": f"visualization:{methods_viz_id}",
        "_type": "doc",
        "_source": {
            "visualization": {
                "title": "HTTP Methods Distribution",
                "visState": json.dumps({
                    "title": "HTTP Methods Distribution",
                    "type": "pie",
                    "params": {
                        "type": "pie",
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "isDonut": True
                    },
                    "aggs": [
                        {
                            "id": "1",
                            "enabled": True,
                            "type": "count",
                            "schema": "metric",
                            "params": {}
                        },
                        {
                            "id": "2",
                            "enabled": True,
                            "type": "terms",
                            "schema": "segment",
                            "params": {
                                "field": "proxy_http_request.http_method",
                                "size": 10,
                                "order": "desc",
                                "orderBy": "1"
                            }
                        }
                    ]
                }),
                "uiStateJSON": "{}",
                "description": "Distribution of HTTP methods",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": index_pattern,
                        "filter": [],
                        "query": {"query": "", "language": "lucene"}
                    })
                }
            },
            "type": "visualization"
        }
    }
    visualizations.append(methods_visualization)
    
    # 7. Dashboard Object
    dashboard_object = {
        "_id": f"dashboard:{dashboard_id}",
        "_type": "doc",
        "_source": {
            "dashboard": {
                "title": "OCSF Network Activity Dashboard",
                "hits": 0,
                "description": "Comprehensive view of network activity from Apache logs",
                "panelsJSON": json.dumps([
                    {
                        "panelIndex": "1",
                        "gridData": {
                            "x": 0,
                            "y": 0,
                            "w": 24,
                            "h": 8,
                            "i": "1"
                        },
                        "id": traffic_viz_id,
                        "type": "visualization",
                        "version": "6.8.2"
                    },
                    {
                        "panelIndex": "2",
                        "gridData": {
                            "x": 0,
                            "y": 8,
                            "w": 12,
                            "h": 10,
                            "i": "2"
                        },
                        "id": status_viz_id,
                        "type": "visualization",
                        "version": "6.8.2"
                    },
                    {
                        "panelIndex": "3",
                        "gridData": {
                            "x": 12,
                            "y": 8,
                            "w": 12,
                            "h": 10,
                            "i": "3"
                        },
                        "id": methods_viz_id,
                        "type": "visualization",
                        "version": "6.8.2"
                    },
                    {
                        "panelIndex": "4",
                        "gridData": {
                            "x": 0,
                            "y": 18,
                            "w": 24,
                            "h": 10,
                            "i": "4"
                        },
                        "id": agents_viz_id,
                        "type": "visualization",
                        "version": "6.8.2"
                    },
                    {
                        "panelIndex": "5",
                        "gridData": {
                            "x": 0,
                            "y": 28,
                            "w": 24,
                            "h": 10,
                            "i": "5"
                        },
                        "id": ips_viz_id,
                        "type": "visualization",
                        "version": "6.8.2"
                    }
                ]),
                "optionsJSON": json.dumps({
                    "darkTheme": False,
                    "hidePanelTitles": False,
                    "useMargins": True
                }),
                "version": 1,
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {
                            "language": "lucene",
                            "query": ""
                        },
                        "filter": []
                    })
                }
            },
            "type": "dashboard"
        }
    }
    visualizations.append(dashboard_object)
    
    return visualizations

def write_ndjson(visualizations, output_file):
    """Write visualizations to NDJSON file format for import into OpenSearch Dashboards"""
    with open(output_file, 'w') as f:
        for viz in visualizations:
            f.write(json.dumps(viz) + '\n')
            
    logger.info(f"Successfully wrote NDJSON visualizations to {output_file}")
    logger.info(f"To import, use: curl -X POST 'http://YOUR_OPENSEARCH_DASHBOARDS_HOST:5601/api/saved_objects/_import' -H 'kbn-xsrf: true' --form file=@{output_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate OCSF Network Activity visualizations for OpenSearch Dashboards')
    parser.add_argument('--host', required=True, help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (for self-signed certificates)')
    parser.add_argument('--index-pattern', default='ocsf-1.1.0-4001-network_activity-*', help='Index pattern for visualizations')
    parser.add_argument('--output', default='ocsf_network_visualizations.ndjson', help='Output NDJSON file path')

    args = parser.parse_args()
    
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
    
    # Generate visualizations
    visualizations = generate_visualizations(args.index_pattern)
    
    # Write to NDJSON file
    write_ndjson(visualizations, args.output)

if __name__ == "__main__":
    main()