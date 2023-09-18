import os
import json
import subprocess
from APIKEY import APIKEY_TRIAGE

result_folder = "./json"
yara_rule_list = []
URL_TRIAGE_YARA = "https://tria.ge/api/v0/yara/"

for file_name in os.listdir(result_folder):
	file_path = os.path.join(result_folder, file_name)

	with open(file_path, "r") as json_file:
		try:
			json_data = json.load(json_file)
			signatures = json_data.get("signatures")
            
			if signatures:
				for signature in signatures:
					if "indicators" in signature:
						indicators = signature["indicators"]
						for indicator in indicators:
							yara_rule = indicator.get("yara_rule")
							if yara_rule:
								if yara_rule not in yara_rule_list:
									yara_rule_list.append(yara_rule)
		except json.JSONDecodeError as e:
			print(f"Error decoding JSON for {file_path}: {e}")

for yara_rule in yara_rule_list:
	yara_cmd = [
		"curl",
		"--request",
		"GET",
		"--url",
		f"{URL_TRIAGE_YARA}{yara_rule}.yara",
		"--header",
		f"Authorization: Bearer {APIKEY_TRIAGE}"
	]

	yara_result = subprocess.run(yara_cmd, capture_output=True, text=True)
	yara_output = yara_result.stdout.strip()

	try:
		yara_json = json.loads(yara_output)

		if yara_json.get("error"):
			print(f"Yara not found with {yara_rule}")
		else:			
			output_file = f"./result.yara"
			with open(output_file, "a") as json_file:
				json.dump(yara_json.get("rule"), json_file, indent=4)
				json_file.write("\n")

	except json.JSONDecodeError as e:
		print(f"Error decoding JSON for {file_name}: {e}")