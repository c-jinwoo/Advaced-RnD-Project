import os
import csv
import json
import datetime
import requests
import subprocess
from APIKEY import APIKEY_VIRUSTOTAL

output_list = [["Hash", "First Time Submission", "Last Analysis 1", "Label Family 1", "Last Analysis 2", "Label Family 2", "Type of C2"]]
avc_cmd = [
    "avclass", "-f"
]
vt_url = "https://www.virustotal.com/api/v3/files/"
headers = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
family_list = ["BruteRatel/", "CobaltStrike/", "Covenant/", "Deimos/", "MetaSploit/", "Posh/", "Sliver/"]


def timestamp2date(time_stamp):
    return datetime.datetime.fromtimestamp(time_stamp).strftime("%Y-%m-%d")

for family in family_list:
    folder_path_old = "./json_old/"
    folder_path_new = "./json_new/"
    json_files = os.listdir(folder_path_old + family)
    
    for json_file in json_files:
        file_result_list = []

        # Append MD5
        file_hash = json_file.split(".")[0]
        file_result_list.append(file_hash)

        # Append Old First Submission Date, Last Analysis Date
        with open(os.path.join(folder_path_old + family, json_file), "r") as file:
            json_content = json.load(file)
            json_data = json_content["data"]["attributes"]        
            file_result_list.append(timestamp2date(json_data["first_submission_date"]))
            file_result_list.append(timestamp2date(json_data["last_analysis_date"]))

        # Append Old Family
        family_cmd = avc_cmd + [f"{folder_path_old}{family}{json_file}"]        
        family_result = subprocess.run(family_cmd, capture_output=True, text=True)
        family_output = family_result.stdout.strip()   
        try: 
            family_name = family_output.split("\t")[1:][0]
            file_result_list.append(family_name)
        except:
            file_result_list.append(family_output)

        # Append New Last Analysis Date
        with open(os.path.join(folder_path_new + family, json_file), "r") as file:
            json_content = json.load(file)
            json_data = json_content["data"]["attributes"]
            file_result_list.append(timestamp2date(json_data["last_analysis_date"]))

        # Append New Family
        family_cmd = avc_cmd + [f"{folder_path_new}{family}{json_file}"]
        family_result = subprocess.run(family_cmd, capture_output=True, text=True)
        family_output = family_result.stdout.strip()

        try:
            family_name = family_output.split("\t")[1:][0]
            file_result_list.append(family_name)
        except:
            file_result_list.append(family_output)

        file_result_list.append(family.split("/")[0])
        
        # Append file_result_list
        output_list.append(file_result_list)


with open("output.csv", "w") as file:
    writer = csv.writer(file)
    writer.writerows(output_list)