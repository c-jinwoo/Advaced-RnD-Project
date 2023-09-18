import os
import csv
import json
import shutil
import argparse
import requests
import subprocess
from APIKEY import APIKEY_VIRUSTOTAL

JSON_DIR         = "./json"
YARA_DIR         = "./yara"
MW_DIR           = "./mw"
VT_JSON_DIR      = "./vt_json"
VT_STATISTICS_DIR= "./vt_stat"
vt_url           = "https://www.virustotal.com/api/v3/files/"
headers          = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}

def vt_report():
    shutil.rmtree(JSON_DIR, ignore_errors=True)
    os.makedirs(JSON_DIR)

    for file in os.listdir(MW_DIR):
        file_name = f"{file}"
        
        # Get response from VirusTotal
        vt_response = requests.get(vt_url + file_name, headers=headers)

        # Write JSON report
        json_path = os.path.join(JSON_DIR, f"{file_name}.json")

        with open(json_path, "w") as json_file:
            json.dump(json.loads(vt_response.text), json_file)


def vt_stat():
    os.makedirs(VT_STATISTICS_DIR, exist_ok=True)

    added_data = {}

    for folder_name in os.listdir(VT_JSON_DIR):
        folder_path = os.path.join(VT_JSON_DIR, folder_name)
        if os.path.isdir(folder_path):
            csv_file_path = os.path.join(VT_STATISTICS_DIR, f"{folder_name}.csv")
            
            added_data[folder_name] = set()

            with open(csv_file_path, mode="w", newline="", encoding="utf-8") as csv_file:
                csv_writer = csv.writer(csv_file)

                # CSV header
                csv_writer.writerow(["source", "ruleset_name", "rule_name"])
                
                # Handle JSON file
                for json_file_name in os.listdir(folder_path):
                    json_file_path = os.path.join(folder_path, json_file_name)
                    
                    with open(json_file_path, mode="r", encoding="utf-8") as json_file:
                        json_data = json.load(json_file)
                        attributes = json_data.get("data", {}).get("attributes", {})
                        yara_results = attributes.get("crowdsourced_yara_results", [])
                        
                        for result in yara_results:
                            source = result.get("source", "")
                            ruleset_name = result.get("ruleset_name", "")
                            rule_name = result.get("rule_name", "")
                            
                            # Check for duplicates
                            if(source, ruleset_name, rule_name) not in added_data[folder_name]:
                                csv_writer.writerow([source, ruleset_name, rule_name])
                                added_data[folder_name].add((source, ruleset_name, rule_name))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="vt_report", type=str)
    args = parser.parse_args()   
        
    if args.mode == "vt_report":
        vt_report()
    elif args.mode == "vt_stat":
        vt_stat()