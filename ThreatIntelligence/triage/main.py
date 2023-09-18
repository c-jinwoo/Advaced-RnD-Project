import os
import yara

def detect_malware(rule_file, mw_file, output_file):
	rules = yara.compile(filepath=rule_file)
	matches = rules.match(mw_file)
	if matches:
		with open(output_file, "a") as f:
			for match in matches:
				f.write(f"[{rule_file.split('/')[2]},{match.rule},{mw_file.split('/')[2]}]\n")

rule_directory = "./rules/"
mw_directory = "./mw/"
output_file = "output.txt"

for root, dirs, files in os.walk(rule_directory):
	for file in files:
		if file.endswith(".yara"):
			rule_file = os.path.join(root, file)
			for mw_file in os.listdir(mw_directory):
				mw_path = os.path.join(mw_directory, mw_file)
				detect_malware(rule_file, mw_path, output_file)