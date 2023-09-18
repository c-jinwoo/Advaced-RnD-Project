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
malware_folder_path = "./mw/"

# Save old JSON
for family in family_list:
    file_names = os.listdir(malware_folder_path + family)
    
    for file_name in file_names:
        file_prefix = file_name.split(".")[0]
        
        if file_prefix.find("_") > 0:
            file_hash = file_prefix.split("_")[1]
        else:
            file_hash = file_prefix
            
        response = requests.get(vt_url + file_hash, headers=headers)
        
        with open(os.path.join(folder_path_old + family, file_hash + ".json"), "w") as json_file:
            json.dump(json.loads(response.text), json_file)