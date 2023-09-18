import requests
import argparse
from APIKEY import APIKEY_LOLDRIVER

# Usage
url = f'https://www.virustotal.com/vtapi/v2/file/report'

def get_virustotal_result(api_key, file_hash):
    params = {'apikey': api_key, 'resource': file_hash}

    response = requests.get(url, params=params)
    response_json = response.json()

    if response.status_code == 200:
        if response_json['response_code'] == 1:
            print(f'${file_hash} found in VirusTotal database.')
            """
            positives = response_json['positives']
            total = response_json['total']
            scan_results = response_json['scans']

            print(f'File Hash: {file_hash}')
            print(f'Positives: {positives}/{total}')
            print('Scan Results:')

            for scanner, result in scan_results.items():
                print(f'{scanner}: {result["result"]}')
            """
        else:
            print(f'${file_hash} not found in VirusTotal database.')
    else:
        print('Error occurred while querying VirusTotal.')
        print(f'Status Code: {response.status_code}')
        print(f'Response: {response_json}')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", default="input.txt", type=str)
    args = parser.parse_args()

    with open(args.input_file, mode="r") as file:
        for line in file:
            get_virustotal_result(APIKEY_LOLDRIVER, line)

