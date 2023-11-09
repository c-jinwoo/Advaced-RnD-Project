import os
import json
from ghidra.program.model.symbol import SourceType

JSON_RESULT = "./ghidra_result.json"
api_list = list()
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getExternalFunctions()
file_name = currentProgram.getExecutableSHA256()

# Save API list
for func in functions:
    func_name = func.getName()
    dll_name = str(func).split("::")[0].split(".")[0]
    api_list.append((func_name, dll_name))

        
# Save JSON        
if len(api_list) > 0:
    data = {
        "api_list": api_list
    }
    
    json_data = []            
    json_data.append(data)
    
    with open(JSON_RESULT, "w") as file:
        json.dump(json_data, file, indent=4)

