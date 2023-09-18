import os
import json
import subprocess
from APIKEY import APIKEY_TRIAGE

FILE_PATH = "./mw"
FILE_PREFIX = "file=@"
URL_TRIAGE = "https://tria.ge/api/v0/samples/"
curl_list = [
    "curl",
    "-H",
    "Authorization: Bearer " + APIKEY_TRIAGE
]
file_name_list = []
sample_id_list = []

for entry in os.scandir(FILE_PATH):
    if entry.is_dir():                                                          # Iterate for all family folders
        folder_name = entry.name                                
        file_dir = os.path.join(FILE_PATH, folder_name)                         # ./mw/FOLDER_NAME/
        file_names = os.listdir(file_dir)                                       # List up mws in each folder
        
        for file_name in file_names:
            file_path_join = os.path.join(file_dir, file_name)                  # ./mw/FOLDER_NAME/FILE_NAME
            file_cmd = curl_list + ["-F"] + [FILE_PREFIX + file_path_join, URL_TRIAGE]
            file_result = subprocess.run(file_cmd, capture_output=True, text=True)
            file_output = file_result.stdout.strip()
            print(file_output)

            try:
                file_json = json.loads(file_output)
                sample_id = file_json.get("id")
                file_name_list.append(file_name)
                sample_id_list.append(sample_id)                                # Append result ID into sample_id_list  

            except json.JSONDecodeError as e:
                print(f"Error decoding JSON for {file_name}: {e}")

        for sample_id in sample_id_list:                                        # Iterate ID list to obtain JSON report
            sample_cmd = curl_list + [URL_TRIAGE + sample_id + "/behavioral1/report_triage.json"]
            sample_result = subprocess.run(sample_cmd, capture_output=True, text=True)
            sample_output = sample_result.stdout.strip()

            try:
                sample_json = json.loads(sample_output)		
                md5_value = sample_json.get("sample", {}).get("md5")

                os.makedirs(f"./{folder_name}", exist_ok=True)                  # Create folder if not exists
                               
                output_file = f"./{folder_name}/{md5_value}.json"               # Save result JSON with its MD5 hash
                with open(output_file, "w") as json_file:
                    json.dump(sample_json, json_file, indent=4)
                    json_file.write("\n")

            except json.JSONDecodeError as e:
                print(f"Error decoding JSON for {sample_id}: {e}")