import os
import sys
import shutil
import subprocess

GHIDRA_BIN	= "support/analyzeHeadless"				# Path for Ghidra executable binary file
PROJECT_DIR = "project/"							# Path for saveing the project
BIN_DIR		= "bin/"								# Path for loading the binary
SCRIPT_DIR	= "ghidraCFG.py"						# Ghidra script to load

def exec(nm_project, nm_bin) :
	cmd_tokens = [
		GHIDRA_BIN, 
		PROJECT_DIR,
		nm_project,
		"-import",
		nm_bin,
		"-postScript",
		SCRIPT_DIR
	]
		
	try:
		subprocess.call(cmd_tokens)

	except:
		print("Error executing subprocess")


if __name__ == "__main__" :
	if len(sys.argv) < 2:
		sys.exit("Usage : python main.py PROJECT_NAME BINARY_FILE")

	project_name = sys.argv[1]
	bin_name = sys.argv[2]

	if not os.path.exists(GHIDRA_BIN):
		sys.exit("Ghidra executable not found")

	if not os.path.exists(PROJECT_DIR):
		sys.exit("Project folder not found")
		
	if not os.path.exists(SCRIPT_DIR):
		sys.exit("Script file not found")

	if not os.path.exists(BIN_DIR + bin_name):
		sys.exit("Binary file not found")

	if os.path.exists(PROJECT_DIR + project_name):
		shutil.rmtree(PROJECT_DIR + project_name)
		shutil.rmtree(PROJECT_DIR + project_name + ".rep")
		os.remove(PROJECT_DIR + project_name + ".gpr")

	os.mkdir(PROJECT_DIR + project_name)
	
	exec(project_name, BIN_DIR + bin_name)


