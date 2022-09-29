import json

import requests

base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0' 
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
      
      data = {}
      if response.status_code == 200:
        data = response.json()
      
      vulnerabilities = data.get('vulnerabilities')
      for vulnerability in vulnerabilities:
        metric_info = vulnerability['cve']['metrics'].get('cvssMetricV31')
        if not metric_info:
          metric_info = vulnerability['cve']['metrics'].get('cvssMetricV2')
        for prop in metric_info:
          base_score = prop['cvssData']['baseScore']
          base_severity = prop['cvssData']['baseSeverity']
          scores.append({ 
                         'base_score': base_score, 
                         'base_severity': base_severity 
                        })
          
max_score = max(scores, key=lambda x:x['base_score'])
print(f'The risk: {max_score["base_severity"]}')
