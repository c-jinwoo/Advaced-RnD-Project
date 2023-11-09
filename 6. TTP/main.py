# TTP(Capa) statistics with Reflective Loader
import os
import csv
import json
import shutil
import argparse
import requests
import subprocess
from APIKEY import APIKEY_VIRUSTOTAL

mw_dir          = "./mw"
JSON_VT_DIR     = "./json/virustotal"
JSON_PARSE_DIR  = "./json/capa_parsed"
CAPA_DIR        = "./capa_result"
vt_url          = "https://www.virustotal.com/api/v3/files/"
headers         = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
avc_cmd = [
    "avclass", "-f"
]
function_statistics = {}

def capa_report():
    shutil.rmtree(CAPA_DIR, ignore_errors=True)
    os.makedirs(CAPA_DIR)

    for file in os.listdir(mw_dir):
        mw_name = f"{file}"
        
        command = [
            "../capa/capa.exe",
            f"{mw_dir}/{mw_name}"
        ]
        
        output_file = f"{CAPA_DIR}/{mw_name}.txt"
        
        with open(output_file, 'w') as output:
            subprocess.run(command, stdout=output)


def read_tabular_new(inp_file):        
    first_head = ['ATT&CK Tactic', 'ATT&CK Technique']
    sec_head = ['MBC Objective', 'MBC Behavior']
    last_head = ['CAPABILITY', 'NAMESPACE']
    temp_data = {
        first_head[0]: {first_head[1]: {}}, 
        sec_head[0]: {sec_head[1]: {}}, 
        last_head[0]: {last_head[1]: {}}
    }    

    with open(inp_file, 'r', encoding='UTF8') as f:           
        root_key, sub_key = None, None
        for line in f.readlines(): 
            line = line.strip('\n')            
            if line and '+' not in line or '-' not in line:                 
                line = line.split('│')
                line = list(filter(None, line))    
                if len(line) == 2:
                    key = line[0].strip()
                    value = line[1].strip()                                       
                    if key == first_head[0]:
                        root_key = key
                        sub_key = first_head[1]
                    if key == sec_head[0]:
                        root_key = key
                        sub_key = sec_head[1]
                    if key == last_head[0]:
                        root_key = key
                        sub_key = last_head[1]
                    
                    if not key:
                        if root_key:
                            last_key = list(temp_data[root_key][sub_key])[-1]                         
                            last_item = temp_data[root_key][sub_key].get(last_key)                        
                            if not isinstance(last_item, list):
                                temp_data[root_key][sub_key].update({last_key: [last_item]})
                            temp_data[root_key][sub_key][last_key].append(value)
                        else:
                            last_key = list(temp_data)[-1]                         
                            last_item = temp_data.get(last_key)                        
                            if not isinstance(last_item, list):
                                temp_data.update({last_key: [last_item]})
                            temp_data[last_key].append(value)                        
                    else:
                        if value in first_head or value in sec_head or value in last_head: 
                            continue
                        if root_key:                                                        
                            temp_data[root_key][sub_key][key] = value
                        else:
                            temp_data[key] = value
                        
    return json.dumps(temp_data, indent=2)


def capa_parse():
    shutil.rmtree(JSON_PARSE_DIR, ignore_errors=True)
    os.makedirs(JSON_PARSE_DIR)

    for file in os.listdir(CAPA_DIR):
        mal_capa_result = f"{CAPA_DIR}/{file}"
        if os.path.getsize(mal_capa_result) !=0:
            json_object = read_tabular_new(f'{CAPA_DIR}/{file}')
            file_name = mal_capa_result.split("/")[2].split(".")[0]
            with open(f"{JSON_PARSE_DIR}/{file_name}.json", "w") as outfile:
                outfile.write(json_object)


def statistics_report():
    shutil.rmtree(JSON_VT_DIR, ignore_errors=True)
    os.makedirs(JSON_VT_DIR)

    for file in os.listdir(JSON_PARSE_DIR):
        file_name = f"{file}".split(".")[0]

        # Get response from VirusTotal
        vt_response = requests.get(vt_url + file_name, headers=headers)
        
        # Write JSON report
        json_path = os.path.join(JSON_VT_DIR, f"{file_name}.json")
        with open(json_path, "w") as json_file:
            json.dump(json.loads(vt_response.text), json_file)
        
        # Get response from Avclass
        family_cmd = avc_cmd + [json_path] 
        family_result = subprocess.run(family_cmd, capture_output=True, text=True)
        family_output = family_result.stdout.strip()
        try: 
            family_name = family_output.split("\t")[1:][0]
        except:
            family_name = family_output

        # Save in Dictionary
        with open(f"{JSON_PARSE_DIR}/{file_name}.json", "r") as json_file:
            data = json.load(json_file)
            tactic = data.get("ATT&CK Tactic", {})
            technique = tactic.get("ATT&CK Technique", {})
            
            for category, values in technique.items():
                if isinstance(values, list):
                    for value in values:
                        technique_parts = value.split()
                        ttp_name = technique_parts[-1]
                        
                        if ttp_name not in function_statistics:                                
                            function_statistics[ttp_name] = {
                                "Description": " ".join(technique_parts[:-1]),
                                "Occurence": 1,
                                "Family": {family_name: 1},
                            }
                        
                        else:
                            # Add occurence    
                            function_statistics[ttp_name]["Occurence"] += 1

                            # Add family
                            if family_name in function_statistics[ttp_name]["Family"]:
                                function_statistics[ttp_name]["Family"][family_name] += 1
                            else:
                                function_statistics[ttp_name]["Family"][family_name] = 1


    # Save CSV
    with open("result.csv", "w", newline="") as csvfile:
        fieldnames = ["TTP", "Description", "Occurence", "Family"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ttp_name, stats in function_statistics.items():
            writer.writerow({
                "TTP": ttp_name,
                "Description": stats["Description"],
                "Occurence": stats["Occurence"],
                "Family": json.dumps(stats["Family"], ensure_ascii=False)
            })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="capa_report", type=str)
    args = parser.parse_args()   
        
    if args.mode == "capa_report":
        capa_report()
    elif args.mode == "capa_parse":
        capa_parse()
    elif args.mode == "statistics_report":
        statistics_report()