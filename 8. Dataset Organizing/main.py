import os
import csv
import json
import shutil
import argparse
import datetime
import requests
import subprocess
import networkx as nx
from APIKEY import APIKEY_VIRUSTOTAL

MW_DIR          = "./mw"
YARA_DIR        = "./yara"
YARA_RESULT_TXT = "./yara_result.txt"
CAPA_RESULT_TXT = "./capa_result.txt"
GHIDRA_BIN      = "../ghidra/support/analyzeHeadless"   
GHIDRA_PROJ_DIR = "../ghidra/project/"
GHIDRA_PROJ_NM  = "grad_proj_2"
GHIDRA_API_SCRIPT   = "ghidra_api.py"
GHIDRA_RESULT_JSON  = "./ghidra_result.json"
GHIDRA_CFG_DIR      = "./cfg/"
FINAL_RESULT_DIR    = "./result2"
vt_url          = "https://www.virustotal.com/api/v3/files/"
headers         = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
avc_cmd         = [
    "avclass", "-f"
]

# Timestamp to Date
def timestamp2date(time_stamp):
    return datetime.datetime.fromtimestamp(time_stamp).strftime("%Y-%m-%d")


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


def get_ttp_list(family, file_hash):
    ttp_list = list()

    capa_cmd = [
        "../capa/capa.exe",
        f"{MW_DIR}/{family}/{file_hash}"
    ]

    with open(CAPA_RESULT_TXT, "w") as output:
        subprocess.run(capa_cmd, stdout=output)

    if os.path.getsize(CAPA_RESULT_TXT) !=0:
        json_object = read_tabular_new(CAPA_RESULT_TXT)
        data = json.loads(json_object)
        tactic = data.get("ATT&CK Tactic", {})
        technique = tactic.get("ATT&CK Technique", {})

        for category, values in technique.items():
            if isinstance(values, list):
                for value in values:
                    technique_parts = value.split()
                    ttp_name = technique_parts[-1]

                    if ttp_name not in ttp_list:
                        ttp_list.append(ttp_name)

    return ttp_list


def get_yara_list(file_hash):
    yara_list = list()

    with open(YARA_RESULT_TXT, "r") as file:
        for line in file:
            yara_name = line.strip().split(" ")[0]
            file_name = line.strip().split(" ")[1].split("/")[3]

            if file_hash == file_name:
                yara_list.append(yara_name)

    return yara_list


def get_api_list(family, file_hash):     
    # Remove existing Ghidra files
    shutil.rmtree(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}", ignore_errors=True)
    shutil.rmtree(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}.rep", ignore_errors=True)

    if os.path.exists(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}.gpr"):
        os.remove(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}.gpr")

    os.mkdir(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}")

    api_list = list()

    ghidra_cmd = [
        GHIDRA_BIN,
        GHIDRA_PROJ_DIR,
        GHIDRA_PROJ_NM,
        "-import",
        f"{MW_DIR}/{family}/{file_hash}",
        "-postScript",
        GHIDRA_API_SCRIPT
    ]

    try:
        subprocess.call(ghidra_cmd)

        with open(GHIDRA_RESULT_JSON, "r") as json_file:
            data = json.load(json_file)
            
            for item in data:
                api_set_list = item["api_list"]
                
                for (func_name, dll_name) in api_set_list:
                    api_list.append(func_name)

    except:
        print("Error executing subprocess")

    return api_list


def get_fts(file_hash):    
    # Get response from VirusTotal
    response = requests.get(vt_url + file_hash, headers=headers)  

    if response.status_code == 200:
        json_data = response.json()
        json_data = json_data["data"]["attributes"]
        return timestamp2date(json_data["first_submission_date"])

    else:
        return ""


def get_cfg_info(family, file_hash):
    num_nodes = 0
    num_edges = 0
    full_path = f"./src/cfg/{file_hash}"

    if os.path.exists(full_path) and os.path.isdir(full_path):
        for file in os.listdir(full_path):
            dot_file = f"{full_path}/{file}"
            G = nx.DiGraph(nx.drawing.nx_agraph.read_dot(dot_file))
            num_nodes += G.number_of_nodes()
            num_edges += G.number_of_edges()            

    return num_nodes, num_edges


def analyze(family):
    result_dict = dict()
    ttp_list = list()
    yara_list = list()
    api_list = list()

    # YARA cmd per type of C2
    with open(YARA_RESULT_TXT, "w") as output:
        for file in os.listdir(YARA_DIR):
            yara_cmd = [
                "yara",
                f"{YARA_DIR}/{file}",
                f"{MW_DIR}/{family}"
            ]
            subprocess.run(yara_cmd, stdout=output)

    for binary_file in os.listdir(os.path.join(MW_DIR, family)):
        file_hash = f"{binary_file}"
        ttp_list = get_ttp_list(family, file_hash)
        yara_list = get_yara_list(file_hash)
        api_list = get_api_list(family, file_hash)
        first_time_submission = get_fts(file_hash)
        num_nodes, num_edges = get_cfg_info(family, file_hash)

        result_dict[file_hash] = {
            "TTP List"      : ttp_list,
            "YARA List"     : yara_list,
            "API List"      : api_list,
            "First Time Submission" : first_time_submission,
            "Number of Nodes" : num_nodes,
            "Number of Edges" : num_edges,
            "Type of C2"    : f"{family}"
        }

    return result_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="", type=str)
    args = parser.parse_args()

    shutil.rmtree(f"{FINAL_RESULT_DIR}", ignore_errors=True)
    os.mkdir(f"{FINAL_RESULT_DIR}")

    # Pass analyze() with folder(C2) name
    for family in os.listdir(MW_DIR):
        result_dict = analyze(f"{family}")

        filename = f"./{FINAL_RESULT_DIR}/{family}.csv"
        with open(filename, "w", newline="") as csv_file:
            fieldnames = ["Hash", "TTP List", "YARA List", "API List", "First Time Submission", "Number of Nodes", "Number of Edges", "Type of C2"]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)      

            # CSV 파일의 헤더를 쓰기
            writer.writeheader()

            for key, value in result_dict.items():               
                # 딕셔너리 값을 CSV 파일로 쓰기
                row = {"Hash": key}
                row.update(value)
                writer.writerow(row)

                

