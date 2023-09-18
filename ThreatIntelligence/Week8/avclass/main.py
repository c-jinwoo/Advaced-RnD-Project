import os
import csv
import json
import requests
import argparse
import datetime
import subprocess
from APIKEY import APIKEY_VIRUSTOTAL

vt_url = "https://www.virustotal.com/api/v3/files/"
headers = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
output_list = [
    ["Hash", "First Time Submission", "Last Analysis 1", "Label Family 1", "Last Analysis 2", "Label Family 2", "Type of C2"]
]
avc_cmd = [
    "avclass", "-f"
]
malware_root_dir = "./mw"
old_json_root_dir = "./json_old"
new_json_root_dir = "./json_new"

# Timestamp to Date
def timestamp2date(time_stamp):
    return datetime.datetime.fromtimestamp(time_stamp).strftime("%Y-%m-%d")


# Save JSON
def save_json_report(json_root_dir):
    os.makedirs(json_root_dir, exist_ok=True)
        
    for entry in os.scandir(malware_root_dir):
        if entry.is_dir():                                                          # Iterate for all family folders
            family_name = entry.name                                            
            file_names = os.listdir(os.path.join(malware_root_dir, family_name))    # List up mws in each folder
            
            for file_name in file_names:
                response = requests.get(vt_url + file_name, headers=headers)        # Get response from VirusTotal
                
                save_dir = os.path.join(json_root_dir, family_name)
                os.makedirs(save_dir, exist_ok=True)                                # Make dir if directory not exist
                
                with open(os.path.join(save_dir, file_name + ".json"), "w") as json_file:
                    json.dump(json.loads(response.text), json_file)                 # Dump JSON


# Rescan VirusTotal
def rescan_vt():
    for entry in os.scandir(malware_root_dir):
        if entry.is_dir():                                                          # Iterate for all family folders
            family_name = entry.name                                        
            file_names = os.listdir(os.path.join(malware_root_dir, family_name))    # List up mws in each folder
            
            for file_name in file_names:
                requests.post(vt_url + file_name + "/analyse", headers=headers)                


# Subprocess Avclass             
def exec_avclass(result_csv):
    for entry in os.scandir(old_json_root_dir):
        if entry.is_dir():                                                          # Iterate for all family folders
            family_name = entry.name
            json_files = os.listdir(os.path.join(old_json_root_dir, family_name))
            
            for json_file in json_files:
                file_result_list = []

                # Append File Name
                file_hash = json_file.split(".")[0]
                file_result_list.append(file_hash)
                
                # Append Old First Submission Date, Last Analysis Date
                with open(os.path.join(old_json_root_dir, family_name, json_file), "r") as file:
                    json_content = json.load(file)
                    json_data = json_content["data"]["attributes"]        
                    file_result_list.append(timestamp2date(json_data["first_submission_date"]))
                    file_result_list.append(timestamp2date(json_data["last_analysis_date"]))
                    
                # Append Old Family
                family_cmd = avc_cmd + [f"{old_json_root_dir}/{family_name}/{json_file}"]        
                family_result = subprocess.run(family_cmd, capture_output=True, text=True)
                family_output = family_result.stdout.strip()
                
                try: 
                    file_result_list.append(family_output.split("\t")[1:][0])
                except:
                    file_result_list.append(family_output)

                # Append New Last Analysis Date
                with open(os.path.join(new_json_root_dir, family_name, json_file), "r") as file:
                    json_content = json.load(file)
                    json_data = json_content["data"]["attributes"]
                    file_result_list.append(timestamp2date(json_data["last_analysis_date"]))

                # Append New Family
                family_cmd = avc_cmd + [f"{new_json_root_dir}/{family_name}/{json_file}"]
                family_result = subprocess.run(family_cmd, capture_output=True, text=True)
                family_output = family_result.stdout.strip()

                try:
                    family_output_result = family_output.split("\t")[1:][0]
                except:
                    family_output_result = family_output                
                    
                file_result_list.append(family_output_result)
                file_result_list.append(family_name)
                
                # Append file_result_list
                output_list.append(file_result_list)


            with open(result_csv, "w") as file:
                writer = csv.writer(file)
                writer.writerows(output_list)


# Count Family per Types
def count_family(result_csv):    
    type_family_data = {}
    
    for entry in os.scandir(old_json_root_dir):
        if entry.is_dir():
            family_name = entry.name
            json_files = os.listdir(os.path.join(old_json_root_dir, family_name))
            
            for json_file in json_files:
                family_cmd = avc_cmd + [f"{new_json_root_dir}/{family_name}/{json_file}"]
                family_result = subprocess.run(family_cmd, capture_output=True, text=True)
                family_output = family_result.stdout.strip()

                try:
                    family_output_result = family_output.split("\t")[1:][0]
                except:
                    family_output_result = family_output    
                
                if family_name in type_family_data:
                    type_family_data[family_name].append(family_output_result)
                else:
                    type_family_data[family_name] = [family_output_result]
                        
    # Count each type and its family with K, V of type_family_data Dict
    # Record in result Dict 
    result = {}
    for t, subtypes in type_family_data.items():
        subtypes_count = {}
        for st in subtypes:
            subtypes_count[st] = subtypes_count.get(st, 0) + 1
        result[t] = subtypes_count
    
    # Write in CSV with result
    # Type1                | Type2                | Type3        
    # Family1 | Family1Cnt | Family1 | Family1Cnt | Family1 | Family1Cnt
    # Family2 | Family2Cnt | Family2 | Family2Cnt | Family2 | Family2Cnt
    with open(result_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        header = [t for t in result.keys()]
        header = [header[i // 2] if i % 2 == 0 else '' for i in range(len(header) * 2)]
        writer.writerow(header)
        
        max_subtype_count = max(len(subtypes) for subtypes in result.values())
        for i in range(max_subtype_count):
            row = []
            for t, subtypes_count in result.items():
                subtypes = list(subtypes_count.keys())
                counts_list = list(subtypes_count.values())
                if i < len(subtypes):
                    row.extend([subtypes[i], counts_list[i]])
                else:
                    row.extend(['', ''])
            writer.writerow(row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="json_old", type=str)
    parser.add_argument("--csv_avclass", default="output.csv", type=str)
    parser.add_argument("--csv_count", default="count.csv", type=str)
    args = parser.parse_args()    
        
    if args.mode == "json_old":
        save_json_report(old_json_root_dir)
    elif args.mode == "json_new":
        save_json_report(new_json_root_dir)
    elif args.mode == "rescan":
        rescan_vt()
    elif args.mode == "avclass":
        exec_avclass(args.csv_avclass)
    elif args.mode == "count":
        count_family(args.csv_count)
    else:
        print("Error")
        
        