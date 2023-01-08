#!/usr/bin/python3

import json
import time
import requests

# NVD CVE API URL
base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0' 
# HTTP headers of the request
headers = {
  'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0',
  'Content-Type': 'application/json'
}

scores = []

with open('results_task2.json') as json_file:
  cve_data = json.load(json_file)
  for software_name in cve_data:
    for cve in cve_data[software_name]:
      cve_id = cve['CVE_data_meta_ID']
      params = dict(cveId=cve_id)
      response = requests.get(base_url, params=params, headers=headers)
      time.sleep(5)

      data = {}
      if response.status_code == 200:
        data = response.json()

      with open(f'{cve_id}.json', 'w') as f:
        json.dump(data, f)
      
      vulnerabilities = data.get('vulnerabilities')
      for vulnerability in vulnerabilities:
        is_v2 = False
        metric_info = vulnerability['cve']['metrics'].get('cvssMetricV31')
        if not metric_info:
          is_v2 = True
          metric_info = vulnerability['cve']['metrics'].get('cvssMetricV2')
        for prop in metric_info:
          base_score = prop['cvssData']['baseScore']
          base_severity = prop['cvssData']['baseSeverity'] if not is_v2 else prop['baseSeverity']
          scores.append({ 
                         'base_score': base_score, 
                         'base_severity': base_severity 
                        })

print(scores)          
max_score = max(scores, key=lambda x:x['base_score'])
print(f'The risk: {max_score["base_severity"]}')
