"""
    Domain Search
"""

import os
import csv
import json
import subprocess
import requests
import shodan
import argparse
from tqdm import tqdm
from datetime import date, timedelta
from censys.search import CensysHosts
from censys.search import SearchClient
from censys.search import CensysCertificates
from APIKEY import APIKEY_VIRUSTOTAL
from APIKEY import APIKEY_URLSCAN
from APIKEY import APIKEY_SHODAN2

# Parameters
domain_list = list()
today = date.today()
yesterday = today - timedelta(1)
today_date = today.strftime("%Y-%m-%d")
yesterday_date = yesterday.strftime("%Y-%m-%d")
search_sdate = "2022-05-01"
search_edate = "2022-12-31"

# Urlscan config
urlscan_domain = "https://urlscan.io/api/v1/scan/"
urlscan_headers = {
    "API-Key":APIKEY_URLSCAN,
    "Content-Type":"application/json"
}

# Virustotal config
vt_domain = "https://www.virustotal.com/api/v3/urls"
vt_headers = {
    "accept": "application/json",
    "x-apikey": APIKEY_VIRUSTOTAL,
    "content-type": "application/x-www-form-urlencoded"
}

# Censys config
h = CensysHosts()
s = SearchClient()
c = CensysCertificates

# Validation check using Urlscan.io
def validation_check(domain, sdate, edate):
    #data = {"url": domain, "visibility": "public", "date":f"[{sdate} TO {edate}]"}
    data = {"url": domain, "visibility": "public"}
    response = requests.post(urlscan_domain, headers=urlscan_headers, data=json.dumps(data))
    
    if response.status_code == 200:
        print("[", sdate, "~", edate, "]", domain, ": Valid")
    else:
        print("[", sdate, "~", edate, "]", domain, ": Invalid")
    """
    cmd_tokens = [
        "curl",
        "https://urlscan.io/api/v1/search/?q=domain:"+domain+f"&date:[{sdate} TO {edate}]"
    ]
            
    try:
        subprocess.call(cmd_tokens)
    except:
        print("Error executing subprocess")
    """
          
    return response.status_code
    
# Virustotal    
def vt_check(domain, sdate, edate):    
    domain = "url=" + domain
    
    response = requests.post(vt_domain, data=domain, headers=vt_headers)
    
    print(response.text)
       
    
# Shodan
def sd_check(domain, sdate, edate):
    api = shodan.Shodan(APIKEY_SHODAN2)
    query = f"hostname:{domain}"
    #query = "hostname:{} after:{} before:{}".format(domain, sdate, edate)       # Shodan Query String

    results = api.search(query)
    for result in results["matches"]:
        with open("sample.json", "w") as json_file:
            print(json.dump(result, json_file))
        
    
# Censys
def cs_check(domain, sdate, edate):    
    events = h.view_host_events(
        domain, start_time=date(2022, 5, 1), end_time=date(2022, 12, 31)
    )
    print(events)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", default="input_original.txt", type=str)
    parser.add_argument("--output_file", default="output.txt", type=str)
    args = parser.parse_args()

    # Insert domains in the list
    with open(args.input_file, mode="r") as file:
        for line in file:
            domain_list.append(line.strip())
            
            
    # Count and record valid domains        
    isResult = False    
    domain_valid = "[DGA]\n"
    for domain in domain_list:
        result = validation_check(domain, yesterday_date, today_date)        
        
        if result != 200:
            isResult = True
            domain_valid += domain + "\n"
        
        #print(yesterday_date.split("-"))
        vt_check(domain, yesterday_date, today_date)
        #sd_check(domain, yesterday_date, today_date)
        #cs_check(domain, yesterday_date, today_date)
        
    
    # Write to file if there is a result                    
    if isResult:
        if os.path.exists(args.output_file):
            os.remove(args.output_file)
            
        with open(args.output_file, mode="a", newline="\n") as file:
            file.write(domain_valid)
