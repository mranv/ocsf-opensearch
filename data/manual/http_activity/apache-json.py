import re
import json

# Define the path to your Apache access log file
input_log_path = 'raw.log'

# Define the path where you want to save the JSON output
output_json_path = 'access_log_n.json'

# Regular expression pattern to parse Apache log lines
log_pattern = r'(?P<ip>[\d\.]+) - - \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'

# Initialize an empty list to store log entries as dictionaries
log_entries = []

# Open the input log file and read its lines
with open(input_log_path, 'r') as log_file:
    for line in log_file:
        match = re.match(log_pattern, line)
        if match:
            log_entry = match.groupdict()
            log_entries.append(log_entry)

# Save the parsed log entries as JSON
with open(output_json_path, 'w') as json_file:
    json.dump(log_entries, json_file, indent=4)

print(f"Conversion completed. JSON data saved to {output_json_path}")
