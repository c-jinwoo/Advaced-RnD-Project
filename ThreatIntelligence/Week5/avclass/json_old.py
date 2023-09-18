import os
import json
import requests
from APIKEY import APIKEY_VIRUSTOTAL

vt_url = "https://www.virustotal.com/api/v3/files/"
headers = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
folder_path_old = "./json_old"
malware_folder_path = "../triage/mw/"
file_names = os.listdir(malware_folder_path)

# Save old JSON
for file_name in file_names:
    response = requests.get(vt_url + file_name, headers=headers)
    with open(os.path.join(folder_path_old, json_file), "w") as json_file:
        json.dump(json.loads(response.text), json_file)