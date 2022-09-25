#!/usr/bin/python3

import csv
import json

from SoftwareWithCPE import SoftwareWithCPE

cpe_software_list = []

print('Mapping the software to the CPE entries:')
with open('results_task1.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for i, row in enumerate(csv_reader):
        if i == 0:
            continue
        entry = SoftwareWithCPE(row[0], row[1], row[2])
        cpe_software_list.append(entry)
        print(entry.__dict__())

def add_to_map(output_json, software, value):
    try:
        output_json[software['software_name']].append(value)
    except KeyError:
        output_json[software['software_name']] = [value]

def extract_data(cve_data, output_json):
    for cve_item in cve_data['CVE_Items']:   
        CVE_data_meta_ID = cve_item['cve']['CVE_data_meta']['ID']
        print(CVE_data_meta_ID)     
        description = list(map(
            lambda x: x['value'], 
            cve_item['cve']['description']['description_data']
            )
        )
        for node in cve_item['configurations']['nodes']:
            for cpe_match in node['cpe_match']:
                cpe_uri = cpe_match['cpe23Uri']
                for software_CPE in cpe_software_list:
                    software = software_CPE.__dict__()
                    if software['cpe_name'] == cpe_uri:
                        add_to_map(output_json, software, {
                            'CVE_data_meta_ID': CVE_data_meta_ID,
                            'cpe': software['cpe_name'],
                            'description': description
                        })

data = {}

for year in range(2002, 2023):
    with open(f'cve/nvdcve-1.1-{year}.json') as json_file:
        cve_data = json.load(json_file)
        extract_data(cve_data, data)        

with open('results.json', 'w') as json_file:
    json.dump(data, json_file, ensure_ascii=False, indent=4)
