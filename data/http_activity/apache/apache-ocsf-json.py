import re
import json
from datetime import datetime
from user_agents import parse

# Regular expression pattern for Apache combined log format
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^\"]*)" "(?P<user_agent>[^\"]*)"'
)

# Function to parse log line
def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        # Parse timestamp
        dt = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        data['timestamp'] = dt.isoformat()
        # Parse user agent
        user_agent = parse(data['user_agent'])
        data['user_agent_details'] = {
            'original': data['user_agent'],
            'name': user_agent.browser.family,
            'version': user_agent.browser.version_string,
            'os': {
                'name': user_agent.os.family,
                'full': user_agent.os.family + ' ' + user_agent.os.version_string,
                'version': user_agent.os.version_string,
                'device': {
                    'name': user_agent.device.family
                }
            }
        }
        # Convert size to integer
        data['size'] = int(data['size']) if data['size'].isdigit() else 0
        return data
    return None

# Read and parse log file
with open('apache_logs.log', 'r') as file:
    logs = []
    for line in file:
        parsed_line = parse_log_line(line)
        if parsed_line:
            # Construct JSON object in desired format
            log_entry = {
                'observedTimestamp': parsed_line['timestamp'],
                'http': {
                    'response': {
                        'status_code': int(parsed_line['status']),
                        'bytes': parsed_line['size']
                    },
                    'url': parsed_line['url'],
                    'flavor': '1.1',
                    'request': {
                        'method': parsed_line['method']
                    },
                    'user_agent': parsed_line['user_agent_details']
                },
                'attributes': {
                    'data_stream': {
                        'dataset': 'apache.access',
                        'namespace': 'production',
                        'type': 'logs'
                    }
                },
                'event': {
                    'result': 'success' if parsed_line['status'].startswith('2') else 'error',
                    'category': 'web',
                    'name': 'access',
                    'type': 'access',
                    'domain': 'apache.access',
                    'kind': 'event'
                },
                'communication': {
                    'source': {
                        'address': parsed_line['ip'],
                        'ip': parsed_line['ip'],
                        'geo': {
                            'country': 'Unknown',
                            'country_iso_code': 'XX'
                        }
                    }
                },
                'body': line.strip(),
                'traceId': '',
                'spanId': '',
                '@timestamp': parsed_line['timestamp']
            }
            logs.append(log_entry)

# Write to JSON file
with open('parsed_logs.json', 'w') as json_file:
    json.dump(logs, json_file, indent=4)
