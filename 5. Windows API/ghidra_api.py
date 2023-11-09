import os
import json
from ghidra.program.model.symbol import SourceType

VT_JSON_DIR = "./json/virustotal"
JSON_RESULT = "./json/result/result.json"
api_list = list()
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getExternalFunctions()
file_name = currentProgram.getExecutableSHA256()

# Save API list
for func in functions:
    func_name = func.getName()
    dll_name = str(func).split("::")[0].split(".")[0]
    api_list.append((func_name, dll_name))
    
# Find family name    
for file in os.listdir(VT_JSON_DIR):
    if file.endswith(".json") and file_name in file:
        index = file.index("_") + 1
        family_name = file[index:-5]
        
# Save JSON        
if len(api_list) > 0:
    data = {
        "file_name": file_name,
        "family_name": family_name,
        "api_list": api_list
    }
    
    json_data = []
    if os.path.exists(JSON_RESULT):
        with open(JSON_RESULT, "r") as file:
            json_data = json.load(file)
            
    json_data.append(data)
    
    with open(JSON_RESULT, "w") as file:
        json.dump(json_data, file, indent=4)