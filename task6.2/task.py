import json
import random

import requests
from stix2 import Filter, MemoryStore


# retrieve enterprise data
def get_data_from_branch(domain, branch="master"):
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])
src = get_data_from_branch("enterprise-attack")

# get tactics
def get_tactics_by_matrix(src):
    tactics = []
    matrix = src.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])[0]

    for tactic_id in matrix['tactic_refs']:
        tactic = src.get(tactic_id)
        tactics.append({
            "id": tactic.get("id"),
            "external_references": tactic.get("external_references"),
            "name": tactic.get("name"),
            "x_mitre_shortname": tactic.get("x_mitre_shortname"),
            "x_mitre_data_sources": tactic.get("x_mitre_data_sources"),
        })

    return tactics
tactics = get_tactics_by_matrix(src)

# remove deprecated objects
def remove_revoked_deprecated(stix_objects):
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )  # type: ignore
    )

# get tactics and techniques with subtechniques
def map_techiques_to_tactics(src, tactics = []):    
    mapped = {}
    for tactic in tactics:
        tactic_name = tactic.get("x_mitre_shortname")
        mapped[tactic_name] = {}

        techniques_or_subtechniques = src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('kill_chain_phases.phase_name', '=', tactic_name),
            Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
            Filter('external_references.source_name', '=', "mitre-attack"),
        ])

        techniques_or_subtechniques = remove_revoked_deprecated(techniques_or_subtechniques)

        for t in techniques_or_subtechniques: 
            external_id = None
            url = None
            for ref in t.get("external_references"):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id")
                    url = ref.get("url")

            if not external_id:
                continue

            if not t.get("x_mitre_is_subtechnique"):
                if external_id not in mapped[tactic_name]:
                    mapped[tactic_name][external_id] = {
                        "name": t.get("name"),                
                        "url": url,
                        "subtechniques": []
                    }
                else:
                    mapped[tactic_name][external_id].update({
                        "name": t.get("name"),                
                        "url": url
                    }) 
            else:
                [ parent_id, subtechnique_id ] = external_id.split('.')
                if parent_id not in mapped[tactic_name]:
                    mapped[tactic_name][parent_id] = {         
                        "subtechniques": []
                    }
                mapped[tactic_name][parent_id]["subtechniques"].append({
                    "id": subtechnique_id,
                    "name": t.get("name"),
                    "url": url,
                })

    return mapped

mapped = map_techiques_to_tactics(src, tactics)
with open('mapped.json', 'w') as f:
    json.dump(mapped, f)

# flatten techniques to ease randomizing
flat_mapped = {}
for (tactic, techniques) in mapped.items():
    flat_mapped[tactic] = []
    for (technique_id, t) in techniques.items():
        if len(t.get("subtechniques")) == 0:
            flat_mapped[tactic].append({
                "id": technique_id,
                "name": t.get("name"),
                "url": t.get("url")
            })
        else:
            for st in t.get("subtechniques"):
                flat_mapped[tactic].append({
                    "id": f"{technique_id}.{st.get('id')}",
                    "name": f"{t.get('name')}: {st.get('name')}",
                    "url": st.get("url")
                })

with open('flat_mapped.json', 'w') as f:
    json.dump(flat_mapped, f)


# save random generated attack
random_attack = {}
for (tactic, techniques) in flat_mapped.items():
    random_techique = random.choice(techniques)
    print(f"Tactic: {tactic}")
    print(f"Id: {random_techique.get('id')}\tName: {random_techique.get('name')}")
    random_attack[tactic] = random_techique
    
with open('random_attack.json', 'w') as f:
    json.dump(random_attack, f)
