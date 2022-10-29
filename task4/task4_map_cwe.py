import json

from simplified_scrapy import SimplifiedDoc, utils

# open cwe tree
xml = utils.getFileContent("./cwec_latest/cwec_v4.9.xml")
doc = SimplifiedDoc(xml)

# read the mapped cwe ids to cve ids
f = open("cwe.json")
data = json.load(f)
mapped_cwe_list = data.items()
f.close()

data = {}

weaknesses = doc.selects("Weaknesses>Weakness")
for weakness in weaknesses:
    weaknessId = weakness.get("ID")
    for mapped_cwe in mapped_cwe_list:
        cveId, cwe = mapped_cwe
        try:
            dataId = f"{cveId}_{cwe.get('cwe_id')[0]}"
            cweId = int(cwe.get("cwe_id")[0].replace("CWE-", ""))
            if int(weaknessId) == cweId:
                data[dataId] = {}
                data[dataId]["ID"] = weaknessId
                data[dataId]["Name"] = weakness.get("Name")

                weaknessContent = SimplifiedDoc(weakness.get("html"))

                # extract description
                data[dataId]["Description"] = weaknessContent.Description.firstText()

                # extract consequences
                consequences = weaknessContent.selects(
                    "Common_Consequences>Consequence"
                )
                data[dataId]["Consequences"] = []
                for consequence in consequences:
                    consequenceContent = SimplifiedDoc(consequence.get("html"))
                    scope = consequenceContent.selects("Scope>text()")
                    # describes the technical impact that arises if an adversary succeeds in exploiting this weakness
                    impact = consequenceContent.selects("Impact>text()")
                    likelihood = consequenceContent.selects(
                        "Likelihood>text()")
                    note = consequenceContent.selects("Note>text()")
                    data[dataId]["Consequences"].append(
                        {
                            "ID": consequence.get("Consequence_ID"),
                            "Scope": scope,
                            "Impact": impact,
                            "Likelihood": likelihood,
                            "Note": note,
                        }
                    )

                # extract potential mitigations
                mitigations = weaknessContent.selects(
                    "Potential_Mitigations>Mitigation"
                )
                data[dataId]["Mitigations"] = []
                for mitigation in mitigations:
                    mitigationContent = SimplifiedDoc(mitigation.get("html"))
                    phase = mitigationContent.selects("Phase>text()")
                    strategy = mitigationContent.selects("Strategy>text()")
                    description = mitigationContent.selects(
                        "Description>text()")
                    effectiveness = mitigationContent.selects(
                        "Effectiveness>text()")
                    effectiveness_notes = mitigationContent.selects(
                        "Effectiveness_Notes>text()"
                    )
                    data[dataId]["Mitigations"].append(
                        {
                            "ID": mitigation.get("Mitigation_ID"),
                            "Phase": phase,
                            "Strategy": strategy,
                            "Description": description,
                            "Effectiveness": effectiveness,
                            "Effectiveness notes": effectiveness_notes,
                        }
                    )

                # extract applicable platforms
                applicable_platforms = weaknessContent.selects(
                    "Applicable_Platforms")
                data[dataId]["Applicable platforms"] = {}
                # extract language
                data[dataId]["Applicable platforms"]["Language"] = []
                for language in applicable_platforms.Language:
                    data[dataId]["Applicable platforms"]["Language"].append(
                        {
                            "Name": language.Name,
                            "Class": language.Class,
                            "Prevalence": language.Prevalence,
                        }
                    )
                # extract os
                data[dataId]["Applicable platforms"]["Operating system"] = []
                for os in applicable_platforms.Operating_System:
                    data[dataId]["Applicable platforms"]["Operating system"].append(
                        {
                            "Name": os.Name,
                            "Class": os.Class,
                            "Version": os.Version,
                            "CPE_ID": os.CPE_ID,
                            "Prevalence": os.Prevalence,
                        }
                    )
                # extract architecture
                data[dataId]["Applicable platforms"]["Architecture"] = []
                for architecture in applicable_platforms.Architecture:
                    data[dataId]["Applicable platforms"]["Architecture"].append(
                        {
                            "Name": architecture.Name,
                            "Class": architecture.Class,
                            "Prevalence": architecture.Prevalence,
                        }
                    )
                # extract technology
                data[dataId]["Applicable platforms"]["Technology"] = []
                for technology in applicable_platforms.Technology:
                    data[dataId]["Applicable platforms"]["Technology"].append(
                        {
                            "Name": technology.Name,
                            "Class": technology.Class,
                            "Prevalence": technology.Prevalence,
                        }
                    )

                # extract metrics
                data[dataId]["Metrics"] = {}
                data[dataId]["Metrics"]["Technical_Impact"] = weaknessContent.select(
                    "Technical_Impact>text()"
                )
                data[dataId]["Metrics"]["Acquired_Privilege"] = weaknessContent.select(
                    "Acquired_Privilege>text()"
                )
                data[dataId]["Metrics"][
                    "Acquired_Privilege_Layer"
                ] = weaknessContent.select("Acquired_Privilege_Layer>text()")
                data[dataId]["Metrics"][
                    "Internal_Control_Effectiveness"
                ] = weaknessContent.select("Internal_Control_Effectiveness>text()")
                data[dataId]["Metrics"]["Finding_Confidence"] = weaknessContent.select(
                    "Finding_Confidence>text()"
                )
                data[dataId]["Metrics"]["Required_Privilege "] = weaknessContent.select(
                    "Required_Privilege>text()"
                )
                data[dataId]["Metrics"][
                    "Required_Privilege_Layer"
                ] = weaknessContent.select("Required_Privilege_Layer>text()")
                data[dataId]["Metrics"]["Access_Vector"] = weaknessContent.select(
                    "Access_Vector>text()"
                )
                data[dataId]["Metrics"][
                    "Authentication_Strength"
                ] = weaknessContent.select("Authentication_Strength>text()")
                data[dataId]["Metrics"][
                    "Level_Of_Interaction"
                ] = weaknessContent.select("Level_Of_Interaction>text()")
                data[dataId]["Metrics"]["Deployment_Scope"] = weaknessContent.select(
                    "Deployment_Scope>text()"
                )
                data[dataId]["Metrics"]["Business_Impact"] = weaknessContent.select(
                    "Business_Impact>text()"
                )
                data[dataId]["Metrics"][
                    "Likelihood_Of_Discovery"
                ] = weaknessContent.select("Likelihood_Of_Discovery>text()")
                data[dataId]["Metrics"][
                    "Likelihood_Of_Exploit"
                ] = weaknessContent.select("Likelihood_Of_Exploit>text()")
                data[dataId]["Metrics"][
                    "External_Control_Effectiveness"
                ] = weaknessContent.select("External_Control_Effectiveness>text()")
                data[dataId]["Metrics"]["Prevalence"] = weaknessContent.select(
                    "Prevalence>text()"
                )
        except:
            pass

with open("cwe_full.json", "w") as outfile:
    json.dump(data, outfile)
