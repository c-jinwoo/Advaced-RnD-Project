# Yara statistics with Reflective Loader
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
yara_result      = "./yara_result.txt"
vt_url           = "https://www.virustotal.com/api/v3/files/"
headers          = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
avc_cmd = [
    "avclass", "-f"
]
function_statistics = {}

def yara_report():
    with open(yara_result, "w") as output:
        for file in os.listdir(YARA_DIR):
            yara_cmd = [
                "yara",
                f"{YARA_DIR}/{file}",
                MW_DIR
            ]
            subprocess.run(yara_cmd, stdout=output)


def vt_report():
    shutil.rmtree(JSON_DIR, ignore_errors=True)
    os.makedirs(JSON_DIR)

    with open(yara_result, "r") as file:
        for line in file:
            file_name = line.strip().split(" ")[1].split("/")[2]
            
            # Get response from VirusTotal
            vt_response = requests.get(vt_url + file_name, headers=headers)

            # Write JSON report
            json_path = os.path.join(JSON_DIR, f"{file_name}.json")

            if not os.path.exists(json_path):
                with open(json_path, "w") as json_file:
                    json.dump(json.loads(vt_response.text), json_file)


def statistics_report():
    with open(yara_result, "r") as file:
        for line in file:
            yara_name = line.strip().split(" ")[0]
            file_name = line.strip().split(" ")[1].split("/")[2]

            # Get response from Avclass
            json_path = os.path.join(JSON_DIR, f"{file_name}.json")

            family_cmd = avc_cmd + [json_path] 
            family_result = subprocess.run(family_cmd, capture_output=True, text=True)
            family_output = family_result.stdout.strip()
            try: 
                family_name = family_output.split("\t")[1:][0]
            except:
                family_name = family_output

            if yara_name not in function_statistics:                                
                function_statistics[yara_name] = {
                    "Number of samples": 1,
                    "Family": {family_name:1}
                }
            else:
                # Add Number of samples
                function_statistics[yara_name]["Number of samples"] += 1

                # Add family
                if family_name in function_statistics[yara_name]["Family"]:
                    function_statistics[yara_name]["Family"][family_name] += 1
                else:
                    function_statistics[yara_name]["Family"][family_name] = 1


    # Save CSV
    with open("result.csv", "w", newline="") as csvfile:
        fieldnames = ["Yara name", "Number of samples", "Family"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for yara_name, items in function_statistics.items():            
            writer.writerow({
                "Yara name": yara_name,
                "Number of samples": items["Number of samples"],
                "Family": json.dumps(items["Family"], ensure_ascii=False)
            })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="yara_extract", type=str)
    args = parser.parse_args()   
        
    if args.mode == "yara_report":
        yara_report()
    elif args.mode == "vt_report":
        vt_report()
    elif args.mode == "statistics_report":
        statistics_report()