import os
import csv
import sys
import json
import shutil
import argparse
import requests
import subprocess
from APIKEY import APIKEY_VIRUSTOTAL

GHIDRA_BIN      = "../ghidra/support/analyzeHeadless"                   # Path for Ghidra executable binary file
PROJECT_DIR     = "../ghidra/project/"                                  # Path for saving the project
PROJECT_NM      = "API"                                                 # Project name
BIN_DIR         = "./mw/"                                               # Path for loading the binary
SCRIPT_NM       = "ghidra_api.py"                                              # Ghidra script to load
JSON_DIR        = "./json/virustotal"
RESULT_DIR      = "./json/result"
RESULT_JSON     = "./json/result/result.json"
vt_url          = "https://www.virustotal.com/api/v3/files/"
headers         = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL
}
avc_cmd = [
    "avclass", "-f"
]
malapi_dict = {
    "Enumeration" : ["CreateToolhelp32Snapshot", "EnumDeviceDrivers", "EnumProcesses", "EnumProcessModules", "EnumProcessModulesEx", "FindFirstFileA", "FindNextFileA", "GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx", "GetModuleBaseNameA", "GetSystemDefaultLangId", "GetVersionExA", "GetWindowsDirectoryA", "IsWoW64Process", "Module32First", "Module32Next", "Process32First", "Process32Next", "ReadProcessMemory", "Thread32First", "Thread32Next", "GetSystemDirectoryA", "GetSystemTime", "ReadFile", "GetComputerNameA", "VirtualQueryEx", "GetProcessIdOfThread", "GetProcessId", "GetCurrentThread", "GetCurrentThreadId", "GetThreadId", "GetThreadInformation", "GetCurrentProcess", "GetCurrentProcessId", "SearchPathA", "GetFileTime", "GetFileAttributesA", "LookupPrivilegeValueA", "LookupAccountNameA", "GetCurrentHwProfileA", "GetUserNameA", "RegEnumKeyExA", "RegEnumValueA", "RegQueryInfoKeyA", "RegQueryMultipleValuesA", "RegQueryValueExA", "NtQueryDirectoryFile", "NtQueryInformationProcess", "NtQuerySystemEnvironmentValueEx", "EnumDesktopWindows", "EnumWindows", "NetShareEnum", "NetShareGetInfo", "NetShareCheck", "GetAdaptersInfo", "PathFileExistsA", "GetNativeSystemInfo", "RtlGetVersion", "GetIpNetTable", "GetLogicalDrives", "GetDriveTypeA", "RegEnumKeyA", "WNetEnumResourceA", "WNetCloseEnum", "FindFirstUrlCacheEntryA", "FindNextUrlCacheEntryA", "WNetAddConnection2A", "WNetAddConnectionA", "EnumResourceTypesA", "EnumResourceTypesExA", "GetSystemTimeAsFileTime", "GetThreadLocale", "EnumSystemLocalesA"],
    "Injection" : ["CreateFileMappingA", "CreateProcessA", "CreateRemoteThread", "CreateRemoteThreadEx", "GetModuleHandleA", "GetProcAddress", "GetThreadContext", "HeapCreate", "LoadLibraryA", "LoadLibraryExA", "LocalAlloc", "MapViewOfFile", "MapViewOfFile2", "MapViewOfFile3", "MapViewOfFileEx", "OpenThread", "Process32First", "Process32Next", "QueueUserAPC", "ReadProcessMemory", "ResumeThread", "SetProcessDEPPolicy", "SetThreadContext", "SuspendThread", "Thread32First", "Thread32Next", "Toolhelp32ReadProcessMemory", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "VirtualAllocExNuma", "VirtualAlloc2", "VirtualAlloc2FromApp", "VirtualAllocFromApp", "VirtualProtectFromApp", "CreateThread", "WaitForSingleObject", "OpenProcess", "OpenFileMappingA", "GetProcessHeap", "GetProcessHeaps", "HeapAlloc", "HeapReAlloc", "GlobalAlloc", "AdjustTokenPrivileges", "CreateProcessAsUserA", "OpenProcessToken", "CreateProcessWithTokenW", "NtAdjustPrivilegesToken", "NtAllocateVirtualMemory", "NtContinue", "NtCreateProcess", "NtCreateProcessEx", "NtCreateSection", "NtCreateThread", "NtCreateThreadEx", "NtCreateUserProcess", "NtDuplicateObject", "NtMapViewOfSection", "NtOpenProcess", "NtOpenThread", "NtProtectVirtualMemory", "NtQueueApcThread", "NtQueueApcThreadEx", "NtQueueApcThreadEx2", "NtReadVirtualMemory", "NtResumeThread", "NtUnmapViewOfSection", "NtWaitForMultipleObjects", "NtWaitForSingleObject", "NtWriteVirtualMemory", "RtlCreateHeap", "LdrLoadDll", "RtlMoveMemory", "RtlCopyMemory", "SetPropA", "WaitForSingleObjectEx", "WaitForMultipleObjects", "WaitForMultipleObjectsEx", "KeInsertQueueApc", "Wow64SetThreadContext", "NtSuspendProcess", "NtResumeProcess", "DuplicateToken", "NtReadVirtualMemoryEx", "CreateProcessInternal", "EnumSystemLocalesA", "UuidFromStringA"],
    "Evasion" : ["CreateFileMappingA", "DeleteFileA", "GetModuleHandleA", "GetProcAddress", "LoadLibraryA", "LoadLibraryExA", "LoadResource", "SetEnvironmentVariableA", "SetFileTime", "Sleep", "WaitForSingleObject", "SetFileAttributesA", "SleepEx", "NtDelayExecution", "NtWaitForMultipleObjects", "NtWaitForSingleObject", "CreateWindowExA", "RegisterHotKey", "timeSetEvent", "IcmpSendEcho", "WaitForSingleObjectEx", "WaitForMultipleObjects", "WaitForMultipleObjectsEx", "SetWaitableTimer", "CreateTimerQueueTimer", "CreateWaitableTimer", "SetWaitableTimer", "SetTimer", "Select", "ImpersonateLoggedOnUser", "SetThreadToken", "DuplicateToken", "SizeOfResource", "LockResource", "CreateProcessInternal", "TimeGetTime", "EnumSystemLocalesA", "UuidFromStringA"],
    "Spying" : ["AttachThreadInput", "CallNextHookEx", "GetAsyncKeyState", "GetClipboardData", "GetDC", "GetDCEx", "GetForegroundWindow", "GetKeyboardState", "GetKeyState", "GetMessageA", "GetRawInputData", "GetWindowDC", "MapVirtualKeyA", "MapVirtualKeyExA", "PeekMessageA", "PostMessageA", "PostThreadMessageA", "RegisterHotKey", "RegisterRawInputDevices", "SendMessageA", "SendMessageCallbackA", "SendMessageTimeoutA", "SendNotifyMessageA", "SetWindowsHookExA", "SetWinEventHook", "UnhookWindowsHookEx", "BitBlt", "StretchBlt", "GetKeynameTextA"],
    "Internet" : ["WinExec", "FtpPutFileA", "HttpOpenRequestA", "HttpSendRequestA", "HttpSendRequestExA", "InternetCloseHandle", "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "InternetReadFileExA", "InternetWriteFile", "URLDownloadToFile", "URLDownloadToCacheFile", "URLOpenBlockingStream", "URLOpenStream", "Accept", "Bind", "Connect", "Gethostbyname", "Inet_addr", "Recv", "Send", "WSAStartup", "Gethostname", "Socket", "WSACleanup", "Listen", "ShellExecuteA", "ShellExecuteExA", "DnsQuery_A", "DnsQueryEx", "WNetOpenEnumA", "FindFirstUrlCacheEntryA", "FindNextUrlCacheEntryA", "InternetConnectA", "InternetSetOptionA", "WSASocketA", "Closesocket", "WSAIoctl", "ioctlsocket", "HttpAddRequestHeaders"],
    "Anti-Debugging" : ["CreateToolhelp32Snapshot", "GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx", "GetTickCount", "OutputDebugStringA", "CheckRemoteDebuggerPresent", "Sleep", "GetSystemTime", "GetComputerNameA", "SleepEx", "IsDebuggerPresent", "GetUserNameA", "NtQueryInformationProcess", "ExitWindowsEx", "FindWindowA", "FindWindowExA", "GetForegroundWindow", "GetTickCount64", "QueryPerformanceFrequency", "QueryPerformanceCounter", "GetNativeSystemInfo", "RtlGetVersion", "GetSystemTimeAsFileTime", "CountClipboardFormats"],
    "Ransomware" : ["CryptAcquireContextA", "EncryptFileA", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData", "CryptDeriveKey", "CryptSetKeyParam", "CryptGetHashParam", "CryptSetKeyParam", "CryptDestroyKey", "CryptGenRandom", "DecryptFileA", "FlushEfsCache", "GetLogicalDrives", "GetDriveTypeA", "CryptStringToBinary", "CryptBinaryToString", "CryptReleaseContext", "CryptDestroyHash", "EnumSystemLocalesA"],
    "Helper" : ["ConnectNamedPipe", "CopyFileA", "CreateFileA", "CreateMutexA", "CreateMutexExA", "DeviceIoControl", "FindResourceA", "FindResourceExA", "GetModuleBaseNameA", "GetModuleFileNameA", "GetModuleFileNameExA", "GetTempPathA", "IsWoW64Process", "MoveFileA", "MoveFileExA", "PeekNamedPipe", "WriteFile", "TerminateThread", "CopyFile2", "CopyFileExA", "CreateFile2", "GetTempFileNameA", "TerminateProcess", "SetCurrentDirectory", "FindClose", "SetThreadPriority", "UnmapViewOfFile", "ControlService", "ControlServiceExA", "CreateServiceA", "DeleteService", "OpenSCManagerA", "OpenServiceA", "RegOpenKeyA", "RegOpenKeyExA", "StartServiceA", "StartServiceCtrlDispatcherA", "RegCreateKeyExA", "RegCreateKeyA", "RegSetValueExA", "RegSetKeyValueA", "RegDeleteValueA", "RegOpenKeyExA", "RegEnumKeyExA", "RegEnumValueA", "RegGetValueA", "RegFlushKey", "RegGetKeySecurity", "RegLoadKeyA", "RegLoadMUIStringA", "RegOpenCurrentUser", "RegOpenKeyTransactedA", "RegOpenUserClassesRoot", "RegOverridePredefKey", "RegReplaceKeyA", "RegRestoreKeyA", "RegSaveKeyA", "RegSaveKeyExA", "RegSetKeySecurity", "RegUnLoadKeyA", "RegConnectRegistryA", "RegCopyTreeA", "RegCreateKeyTransactedA", "RegDeleteKeyA", "RegDeleteKeyExA", "RegDeleteKeyTransactedA", "RegDeleteKeyValueA", "RegDeleteTreeA", "RegDeleteValueA", "RegCloseKey", "NtClose", "NtCreateFile", "NtDeleteKey", "NtDeleteValueKey", "NtMakeTemporaryObject", "NtSetContextThread", "NtSetInformationProcess", "NtSetInformationThread", "NtSetSystemEnvironmentValueEx", "NtSetValueKey", "NtShutdownSystem", "NtTerminateProcess", "NtTerminateThread", "RtlSetProcessIsCritical", "DrawTextExA", "GetDesktopWindow", "SetClipboardData", "SetWindowLongA", "SetWindowLongPtrA", "OpenClipboard", "SetForegroundWindow", "BringWindowToTop", "SetFocus", "ShowWindow", "NetShareSetInfo", "NetShareAdd", "NtQueryTimer", "GetIpNetTable", "GetLogicalDrives", "GetDriveTypeA", "CreatePipe", "RegEnumKeyA", "WNetOpenEnumA", "WNetEnumResourceA", "WNetAddConnection2A", "CallWindowProcA", "NtResumeProcess", "lstrcatA", "ImpersonateLoggedOnUser", "SetThreadToken", "SizeOfResource", "LockResource", "UuidFromStringA"],
}
function_statistics = {}

def ghidra_report(file_name):    
    # Get response from VirusTotal
    vt_response = requests.get(vt_url + file_name, headers=headers)        
    
    # Write JSON report
    json_path = os.path.join(JSON_DIR, f"{file_name}.json")
    with open(json_path, "w") as json_file:
        json.dump(json.loads(vt_response.text), json_file)
        
    # Get response from Avclass
    family_cmd = avc_cmd + [json_path]        
    family_result = subprocess.run(family_cmd, capture_output=True, text=True)
    family_output = family_result.stdout.strip()

    try: 
        family_name = family_output.split("\t")[1:][0]
    except:
        family_name = family_output
    
    # Re-save JSON with family name
    os.remove(json_path)
    with open(os.path.join(JSON_DIR, f"{file_name}_{family_name}.json"), "w") as json_file:
        json.dump(json.loads(vt_response.text), json_file)
        
    # Execute Headless Ghidra   
    cmd_tokens = [
        GHIDRA_BIN,
        PROJECT_DIR,
        PROJECT_NM,
        "-import",
        BIN_DIR + file_name,
        "-postScript",
        SCRIPT_NM
    ]

    try:
        subprocess.call(cmd_tokens)
    except:
        print("Error executing subprocess")


def statistics_report():  
    with open(RESULT_JSON, "r") as json_file:
        data = json.load(json_file)

    for item in data:
        family_name = item["family_name"]
        api_list = item["api_list"]
        
        for (func_name, dll_name) in api_list:
            # Newly insert API
            if func_name not in function_statistics:
                # Search associated attack in Malapi dict
                att_name = ""
                for att, func_list in malapi_dict.items():
                    if func_name in func_list:
                        att_name = att
                        
                function_statistics[func_name] = {
                    "DLL": dll_name,
                    "Occurence": 1,
                    "Family": {family_name: 1},
                    "Associated": att_name,
                }
                
            else:        
                # Add occurence    
                function_statistics[func_name]["Occurence"] += 1
            
                # Add family
                if family_name in function_statistics[func_name]["Family"]:
                    function_statistics[func_name]["Family"][family_name] += 1
                else:
                    function_statistics[func_name]["Family"][family_name] = 1


    # Save CSV
    with open("result.csv", "w", newline="") as csvfile:
        fieldnames = ["Function", "DLL", "Occurence", "Family", "Associated"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for func_name, stats in function_statistics.items():
            writer.writerow({
                "Function": func_name,
                "DLL": stats["DLL"],
                "Occurence": stats["Occurence"],
                "Family": json.dumps(stats["Family"], ensure_ascii=False),
                "Associated": stats["Associated"],
            })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="ghidra_report", type=str)
    args = parser.parse_args()   
        
    if args.mode == "ghidra_report":
        if not os.path.exists(GHIDRA_BIN):
            sys.exit("Ghidra executable not found")

        if not os.path.exists(PROJECT_DIR):
            sys.exit("Project folder not found")

        if not os.path.exists(SCRIPT_NM):
            sys.exit("Script file not found")

        if os.path.exists(PROJECT_DIR + PROJECT_NM):
            shutil.rmtree(PROJECT_DIR + PROJECT_NM)
            
        if os.path.exists(PROJECT_DIR + PROJECT_NM + ".rep"):
            shutil.rmtree(PROJECT_DIR + PROJECT_NM + ".rep")
            
        if os.path.exists(PROJECT_DIR + PROJECT_NM + ".gpr"):
            os.remove(PROJECT_DIR + PROJECT_NM + ".gpr")
        
        if os.path.exists(JSON_DIR):
            shutil.rmtree(JSON_DIR)
            
        if os.path.exists(RESULT_DIR):
            shutil.rmtree(RESULT_DIR)
            
        os.mkdir(PROJECT_DIR + PROJECT_NM)
        os.mkdir(JSON_DIR)
        os.mkdir(RESULT_DIR)

        for entry in os.scandir(BIN_DIR):
            ghidra_report(entry.name)
    elif args.mode == "statistics_report":
        statistics_report()

    