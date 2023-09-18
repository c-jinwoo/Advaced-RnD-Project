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
json_files = os.listdir(folder_path_old)

for json_file in json_files:
    # Rescan via Virustotal
    requests.post(vt_url + file_hash + "/analyse", headers=headers)