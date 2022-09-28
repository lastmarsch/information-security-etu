#!/usr/bin/python3

import csv
import json

from CPE import CPE
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

def add_to_map(output_json, software_name, value):
    try:
        output_json[software_name].append(value)
    except KeyError:
        output_json[software_name] = [value]

def compare_versions(a, b):
    if (a == None) and (b == None):
       return None
    if (a == None):
        return b
    return a

def extract_data(cve_data, output_json):
    for cve_item in cve_data['CVE_Items']:   
        CVE_data_meta_ID = cve_item['cve']['CVE_data_meta']['ID']  
        description = list(map(
            lambda x: x['value'], 
            cve_item['cve']['description']['description_data']
            )
        )
        for node in cve_item['configurations']['nodes']:
            for cpe_match in node['cpe_match']:
                cpe_uri = cpe_match['cpe23Uri']

                cpe_object = CPE(cpe_uri)

                version_start_excluding = cpe_match.get('versionStartExcluding')
                version_start_including = cpe_match.get('versionStartIncluding')
                version_end_excluding = cpe_match.get('versionEndExcluding')
                version_end_including = cpe_match.get('versionEndIncluding')

                for software in cpe_software_list:
                    software_cpe_object = software.cpe
                    
                    # if vendor and product don't match -> skip
                    if (cpe_object.vendor != software_cpe_object.vendor) or (cpe_object.product != software_cpe_object.product):
                        continue

                    is_version_start_including = software_cpe_object.compare_with_version(version_start_including, '>=')
                    is_version_start_excluding = software_cpe_object.compare_with_version(version_start_excluding, '>')
                    is_version_end_including = software_cpe_object.compare_with_version(version_end_including, '<=')
                    is_version_end_excluding = software_cpe_object.compare_with_version(version_end_excluding, '<')
                    
                    is_version_after_start = compare_versions(is_version_start_including, is_version_start_excluding)
                    is_version_before_end = compare_versions(is_version_end_including, is_version_end_excluding)                    

                    is_match_version = software_cpe_object.version == cpe_object.version
                    is_between_versions = is_version_before_end and is_version_after_start
                    is_between_start_and_inf = is_version_after_start and (is_version_before_end == None)
                    is_between_inf_and_end = (is_version_after_start == None) and is_version_before_end

                    if is_match_version or is_between_versions or is_between_start_and_inf or is_between_inf_and_end:
                        
                        add_to_map(output_json, software.__dict__()['software_name'], {
                            'CVE_data_meta_ID': CVE_data_meta_ID,
                            'cpe': software_cpe_object.assemble_cpe(),
                            'versionStartExcluding': version_start_excluding,
                            'versionStartIncluding': version_start_including,
                            'versionEndExcluding': version_end_excluding,
                            'versionEndIncluding': version_end_including,
                            'description': description
                        })

data = {}

for year in range(2002, 2023):
    with open(f'cve/nvdcve-1.1-{year}.json') as json_file:
        cve_data = json.load(json_file)
        extract_data(cve_data, data)        

with open('results.json', 'w') as json_file:
    json.dump(data, json_file, ensure_ascii=False, indent=4)
