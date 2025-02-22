import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd
import json


file_path = "jso.log"

with open(file_path) as fp: 
    table = fp.read().split("\n")


processed_data=[]

table = table[:-1]

for rec in table:
    # Process data for each row and create json_data dictionary
    row = json.loads(rec)
    activity_name = "Apache"
    http_method = str(row['Method'])
    if str(row['Method']) == "GET":
        activity_id = '3'
        type_uid = '400203'
    elif str(row['Method']) == "POST":
        activity_id = '6'
        type_uid = '400206'
    elif str(row['Method']) == "PUT":
        activity_id = '7'
        type_uid = '400207'
    elif str(row['Method']) == "DELETE":
        activity_id = '2'
        type_uid = '400202'
    else:
        activity_id = '0'
        type_uid = '400299'

    http_request = {'http_method': str(row['Method']),
                          'referrer': str(row['Referer']),
                          'user_agent': str(row['UserAgent']),
                          'interface_id': '',
                          'port': str(row['Port'])}

    http_response = {'status': str(row['Status']),
                 'code': str(row['Status'])}

    time = row['Time']

    metadata = {
        		'product': {
            				'vendor_name': 'Apache',
            				'name': 'Apache System Log',
            				'version': '1.0'
			        	  },
        		'version': '1.0'
        		  }

    app_name = 'Demo Security Lake'

    category_name = 'Apache Logs Events'

    category_uid = '4'

    class_uid = '4002'

    dstdetails = {'hostname': str(row['RemoteIP']),
                          'ip': str(row['RemoteIP']),
                          'instance_uid': '',
                          'interface_id': '',
                          'port': str(row['Port'])}

    srcdetails = {        'hostname': str(row['Host']),
                          'ip': str(row['Host']),
                          'instance_uid': '',
                          'interface_id': '',
                          'port': str(row['Port'])
             }
    http_status = row['Status']

    status = row['Status']


    if str(row['Status']) == '404':
        status_details = '1'
    else:
        status_details = '9'

    severity_id = '1'


    json_data = {'activity_name': activity_name,
        'http_method': http_method,
        'activity_id': activity_id,
        'category_name': category_name,
        'category_uid': category_uid,
        'class_name' : 'HTTP Activity',
        'class_uid': class_uid,
        'dst_endpoint': dstdetails,
        'time': str(time),
        'severity_id': severity_id,
        'src_endpoint': srcdetails,
        'status': str(status),
        'status_code': str(status),
        'status_detail': status_details,
       # 'status_id': status_id,
        'type_uid': type_uid,
        'app_name': app_name,
        'http_request': http_request,
        'http_response':http_response,
        'metadata': metadata}

# Append the json_data to the list
    processed_data.append(json_data)

# Create a Pandas DataFrame from the processed data

df = pd.DataFrame(processed_data)

# Create a PyArrow Table from the Pandas DataFrame

table1 = pa.Table.from_pandas(df)

# Write the PyArrow Table to a Parquet file

pq.write_table(table1, 'result.parquet')