import os
import sys
import shutil
import subprocess

GHIDRA_BIN      = "../../ghidra/support/analyzeHeadless"   
GHIDRA_PROJ_DIR = "../../ghidra/project/"
GHIDRA_PROJ_NM  = "cfg_extraction"
SCRIPT_DIR = "./ghidraCFG-original.py"
BIN_PATH = './bin'

def exec(nm_bin):
    # Remove existing Ghidra files
    shutil.rmtree(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}", ignore_errors=True)
    shutil.rmtree(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}.rep", ignore_errors=True)

    if os.path.exists(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}.gpr"):
        os.remove(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}.gpr")

    os.mkdir(f"{GHIDRA_PROJ_DIR}{GHIDRA_PROJ_NM}")


    ghidra_cmd = [
        GHIDRA_BIN,
        GHIDRA_PROJ_DIR,
        GHIDRA_PROJ_NM,
        "-import",
        f"./bin/{nm_bin}",
        "-postScript",
        SCRIPT_DIR
    ]

    try:
        subprocess.call(ghidra_cmd)

    except:
        print("Error executing subprocess")

        
if __name__ == "__main__":
    for file in os.listdir("./bin"):
        exec(f"{file}")



