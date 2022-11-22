import json
from simplified_scrapy import SimplifiedDoc, utils


f = open('cwe_full_task4.json',)
data = json.load(f)
f.close()

cwe_ids = []
for (id, cwe) in data.items():
    cwe_ids.append(cwe.get('ID'))


xml = utils.getFileContent("./capec_v3.8.xml")
doc = SimplifiedDoc(xml)

def create_attack_patern_object(ap):
    attack_pattern = {}

    attack_pattern["ID"] = int(ap.get("ID"))
    attack_pattern["Name"] = ap.get("Name")
    attack_pattern["Abstraction"] = ap.get("Abstraction")
    attack_pattern["Status"] = ap.get("Status")

    attack_pattern["Description"] = ap.select("Description>text()")
    attack_pattern["Extended_Description"] = ap.select("Extended_Description>text()")
    
    attack_pattern["Alternate_Terms"] = []
    alternate_terms = ap.selects("Alternate_Terms>Alternate_Term")
    for term in alternate_terms:
        attack_pattern["Alternate_Terms"].append({
            "Term": term.select("Term>text()"),
            "Description": term.select("Description>text()")
        })

    attack_pattern["Likelihood_Of_Attack"] = ap.select("Likelihood_Of_Attack>text()")
    attack_pattern["Typical_Severity"] = ap.select("Typical_Severity>text()")

    attack_pattern["Related_Attack_Patterns"] = []
    related_attack_patterns = ap.selects("Related_Attack_Patterns>Related_Attack_Pattern")
    for related_attack_pattern in related_attack_patterns:
        attack_pattern["Related_Attack_Patterns"].append({
            "Exclude_Related": related_attack_pattern.selects("Exclude_Related>Exclude_ID()"),
            "Nature": related_attack_pattern.get("Nature"),
            "CAPEC_ID": related_attack_pattern.get("CAPEC_ID")
        })

    attack_pattern["Execution_Flow"] = []
    attack_steps = ap.selects("Execution_Flow>Attack_Step")
    for step in attack_steps:
        attack_pattern["Execution_Flow"].append({
            "Step": step.select("Step>text()"),
            "Phase": step.select("Phase>text()"),
            "Description": step.select("Description>text()"),
            "Technique": step.selects("Technique>text()")
        })

    
    prerequisites = ap.selects("Prerequisites>Prerequisite>text()")
    attack_pattern["Prerequisites"] = prerequisites

    attack_pattern["Skills_Required"] = []
    skills = ap.selects("Skills_Required>Skill")
    for skill in skills:
        attack_pattern["Skills_Required"].append({
            "Level": skill.get("Level"),
            "Description": skill.select("text()")
        })


    resources = ap.selects("Resources_Required>Resource>text()")
    attack_pattern["Resources_Required"] = resources

    indicators = ap.selects("Indicators>Indicator>text()")
    attack_pattern["Indicators"] = indicators

    attack_pattern["Consequences"] = []
    consequences = ap.selects("Consequences>Consequence")
    for consequence in consequences:
        attack_pattern["Consequences"].append({
            "Scope": consequence.selects("Scope>text()"),
            "Impact": consequence.selects("Impact>text()"),
            "Likelihood": consequence.select("Likelihood>text()"),
            "Note": consequence.select("Note>text()"),
        })
   
    mitigations = ap.selects("Mitigations>Mitigation>text()")
    attack_pattern["Mitigations"] = mitigations

    related_weaknesses = ap.selects("Related_Weaknesses>Related_Weakness>CWE_ID()")
    attack_pattern["Related_Weaknesses"] = related_weaknesses

    attack_pattern["Taxonomy_Mappings"] = []
    taxonomy_mappings = ap.selects("Taxonomy_Mappings>Taxonomy_Mapping")
    for taxonomy_mapping in taxonomy_mappings:
        attack_pattern["Taxonomy_Mappings"].append({
            "Taxonomy_Name": taxonomy_mapping.get("Taxonomy_Name"),
            "Entry_ID": taxonomy_mapping.select("Entry_ID>text()"),
            "Entry_Name": taxonomy_mapping.select("Entry_Name>text()"),
            "Mapping_Fit": taxonomy_mapping.select("Mapping_Fit>text()"),
        })

    return attack_pattern

related_attack_patterns = []
attack_patterns = doc.selects("Attack_Pattern_Catalog>Attack_Patterns>Attack_Pattern")
for ap in attack_patterns:
    related_weaknesses_ids = ap.selects("Related_Weaknesses>Related_Weakness>CWE_ID()")
    
    # if at least one id from cwe_ids is in related_weaknesses_ids,
    # save the attack_pattern
    if bool(set(cwe_ids) & set(related_weaknesses_ids)):
        related_attack_patterns.append(create_attack_patern_object(ap))


# Save attack patterns found in the JSON
related_attack_patterns.sort(key=lambda x: x.get("ID"))
with open("related_attack_patterns.json", "w") as outfile:
    json.dump(related_attack_patterns, outfile)


# Print the result
for cwe_id in cwe_ids:
    print(f"RELATED ATTACK PATTERNS FOR CWE_ID={cwe_id}:\n")
    for ap in related_attack_patterns:
        if cwe_id in ap.get("Related_Weaknesses"):
            print(f"ID={ap.get('ID')},\t{ap.get('Name')}")
            print("\n\tMITIGATIONS:")
            for mitigation in ap.get("Mitigations"):
                print(f"\t- {mitigation}")
            print("\n\tMETRICS:")
            print(f"\t  Likelihood_Of_Attack:\t{ap.get('Likelihood_Of_Attack')}") 
            print(f"\t  Typical_Severity:\t{ap.get('Typical_Severity')}")   
            print("\t  Skills_Required:")   
            for index, skill in enumerate(ap.get("Skills_Required")):
                print(f"\t    {index + 1}")
                print(f"\t    Level:\t\t{skill.get('Level')}")  
                print(f"\t    Description:\t{skill.get('Description')}")           
            print("\t  Consequences:")   
            for index, consequence in enumerate(ap.get("Consequences")):
                print(f"\t    {index + 1}")
                print(f"\t      Scope:\t\t{', '.join(consequence.get('Scope'))}")
                print(f"\t      Impact:\t\t{', '.join(consequence.get('Impact'))}")
                print(f"\t      Likelihood:\t{consequence.get('Likelihood') or '-'}")
        print()
    print()