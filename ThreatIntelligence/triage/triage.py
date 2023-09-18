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

for file_name in os.listdir(FILE_PATH):
	idx = 0
	file_path_join = os.path.join(FILE_PATH, file_name)
	file_cmd = curl_list + ["-F"] + [FILE_PREFIX + file_path_join, URL_TRIAGE]
	file_result = subprocess.run(file_cmd, capture_output=True, text=True)
	file_output = file_result.stdout.strip()
    
	try:
		file_json = json.loads(file_output)
		sample_id = file_json.get("id")
		file_name_list.append(file_name)
		sample_id_list.append(sample_id)

	except json.JSONDecodeError as e:
		print(f"Error decoding JSON for {file_name}: {e}")

for sample_id in sample_id_list:
	sample_cmd = curl_list + [URL_TRIAGE + sample_id + "/overview.json"]
	sample_result = subprocess.run(sample_cmd, capture_output=True, text=True)
	sample_output = sample_result.stdout.strip()
	
	try:
		sample_json = json.loads(sample_output)		
		md5_value = sample_json.get("sample", {}).get("md5")

		output_file = f"./json/{md5_value}.json"
		with open(output_file, "w") as json_file:
			json.dump(sample_json, json_file, indent=4)
			json_file.write("\n")

	except json.JSONDecodeError as e:
		print(f"Error decoding JSON for {sample_id}: {e}")
		
