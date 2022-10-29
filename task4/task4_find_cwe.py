import json


def find_weaknesses():
  f = open('results_full_cve_task2.json',)
  data = json.load(f)
  cve_list = data.get("cve_list")
  f.close()
  
  cwe_data = {}
  
  for item in cve_list:
    cve = item.get("cve")
    
    # get cve id
    cve_id = cve.get("CVE_data_meta").get("ID")
    cwe_data[cve_id] = {}
    cwe = cwe_data[cve_id]
    
    # create the array for cwe_ids in case if there are more than 1 description or problemtype_data
    cwe["cwe_id"] = []
    
    # iterate the problem data and extract cwe ids
    for problemtype_data in cve.get("problemtype").get("problemtype_data"):
      print(problemtype_data)
      for description in problemtype_data.get("description"):
        cwe["cwe_id"].append(description.get("value"))
      
  with open("cwe.json", "w") as outfile:
    json.dump(cwe_data, outfile)

find_weaknesses()






