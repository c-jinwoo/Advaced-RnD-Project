import os
import json
import requests
from APIKEY import APIKEY_VIRUSTOTAL

vt_url = "https://www.virustotal.com/api/v3/files/"
headers = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
family_list = ["BruteRatel/", "CobaltStrike/", "Covenant/", "Deimos/", "MetaSploit/", "Posh/", "Sliver/"]
folder_path_old = "./json_old/"

for family in family_list:
    json_files = os.listdir(folder_path_old + family)    
    
    for json_file in json_files:        
        file_hash = json_file.split(".")[0]
        # Rescan via Virustotal
        requests.post(vt_url + file_hash + "/analyse", headers=headers)