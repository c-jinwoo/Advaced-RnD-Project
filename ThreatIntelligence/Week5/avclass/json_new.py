import os
import json
import requests
from APIKEY import APIKEY_VIRUSTOTAL

vt_url = "https://www.virustotal.com/api/v3/files/"
headers = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
folder_path_new = "./json_new"
file_names = os.listdir(folder_path_new)

# Save new JSON
for file_name in file_names:
    response = requests.get(vt_url + file_name.split(".")[0], headers=headers)
    with open(os.path.join(folder_path_new, json_file), "w") as json_file:
        json.dump(json.loads(response.text), json_file)
    