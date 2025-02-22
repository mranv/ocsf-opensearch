import re
import json

# Define the path to your old Apache access log file
input_log_path = 'access_log'

# Define the path where you want to save the JSON output
output_json_path = 'access_log_n.json'

# Regular expression pattern to parse Apache log lines
log_pattern = r'(?P<ip>[\d\.]+) - - \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<bytes_sent>\d+)'

# Initialize an empty list to store log entries as dictionaries
log_entries = ''

# Open the input log file and read its lines
with open(input_log_path, 'r') as log_file:
    for line in log_file:
        match = re.match(log_pattern, line)
        if match:
            log_entry = match.groupdict()
            log_entries += str(log_entry)
            log_entries += '\n'
            content = str(log_entries)
# Save the parsed log entries as JSON

with open(output_json_path, 'w') as json_file:
    json_file.write(log_entries)

print(f"Conversion completed. JSON data saved to {output_json_path}")