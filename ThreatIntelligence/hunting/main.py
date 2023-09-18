"""
    Hunting C2/Adversaries Infrastructure
"""

import csv
import shodan
import argparse
from tqdm import tqdm
from censys.search import CensysHosts
from censys.search import SearchClient
from censys.search import CensysCertificates
from APIKEY import APIKEY_SHODAN2

# Dictionary for th total result
result_dict = dict()

# Shodan config
shodan_api_key = APIKEY_SHODAN2
shodan_ip_list = list()
shodan_query_list = [
    ["Cobalt Strike C2", "product:'Cobalt+Strike+Beacon' ip:"],
    ["Metasploit/MSF", "ssl:'MetasploitSelfSignedCA' ip:"],
    ["Covenant C2", "ssl:'Covenant' http.component:'Blazor' ip:"],
    ["Mythic C2", "ssl:Mythic+port:7443 ip:"],
    ["Brute Ratel C4", "http.html_hash:-1957161625 ip:"],
    ["Deimos C2", "http.html_hash:-14029177 ip:"],
    ["Posh C2", "ssl:'P18055077' ip:"],
    ["Sliver C2", "ssl.jarm:3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910+'HTTP/1.1+404+Not+Found'+'Cache-Control:+no-store,+no-cache,+must-revalidate'+'Content-Length:+0' ip:"],
    ["C3 from WithSecure", "HTTP/1.1+200+OK+Connection:+close+Content-Length:+712+Accept-Ranges:+bytes+Content-Type:+text/html+Server:+Kestrel ip:"]
]

# Censys config
h = CensysHosts()
s = SearchClient()
c = CensysCertificates

censys_ip_list = list()
censys_query_list = [
    ["Evilginx Infrastructure", "services.http.response.body_hash='sha1:b18d778b4e4b6bf1fd5b2d790c941270145a6a6d' and ip:"],
    ["IcedID Infrastructure",
     "services.tls.certificates.leaf_data.subject_dn='CN=localhost, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd' and ip:"],
    ["Gophish Infrastructure",
     "services.jarm.fingerprint: 28d28d28d00028d00041d28d28d41dd279b0cf765af27fa62e66d7c8281124 and ip:"],
    ["Viper Infrastructure", "services.http.response.body_hash='sha1:cd40dbcdae84b1c8606f29342066547069ed5a33' and ip:"],
    ["ARL/Assessment Reconsassaince Tool Infrastructure",
     "services.http.response.body_hash='sha1:465811beb4dab8e1df19cf2ad3ed92bfd2194de2' and ip:"],
    ["Night Hawk C2", "services.http.response.body_hash='sha1:057f3b5488605b4d224d038e340866e2cdfed4a3' and ip:"],
    ["ShadowPad C2 Infrastructure",
     "services.tls.certificates.leaf_data.subject_dn='C=CN, ST=myprovince, L=mycity, O=myorganization, OU=mygroup, CN=myServer' and ip:"],
    ["Async Rat C2 Infrastructure", "services.tls.certificates.leaf_data.issuer.common_name:AsyncRat and ip:"],
    ["Meterpreter C2 Infrastructure",
     "services.http.response.body_hash='sha1:057f3b5488605b4d224d038e340866e2cdfed4a3' and ip:"]
]


# analyze from Shodan
def shodan_analysis():
    try:
        api = shodan.Shodan(shodan_api_key)

        for qu in shodan_query_list:
            query = " ".join(qu[1])
            result = api.search(query)

            result_list = list()
            for service in result["matches"]:
                result_list.append(service["ip_str"])

            shodan_ip_list.append(result_list)

    except Exception as e:
        print("Shodan Error: %s" % e)


# analyze from Censys
def censys_analysis():
    for query_list in censys_query_list:
        query = h.search(query_list[1])
        results = query()

        result_list = list()
        for result in results:
            result_list.append(result["ip"])
        censys_ip_list.append(result_list)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", default="ip.csv", type=str)
    args = parser.parse_args()

    # Read CSV
    input_ip_list = list()
    with open(args.input_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        data = [row for row in reader]
        for datum in data:
            input_ip_list.append(datum["IP"])

    # shodan_analysis()
    # censys_analysis()

    for ip in tqdm(input_ip_list):
        infra_list = list()

        try:
            api = shodan.Shodan(shodan_api_key)
            for qu in shodan_query_list:
                query = " ".join(qu[1] + ip)
                result = api.search(query)
                if len(result["matches"]) > 0:
                    infra_list.append(qu[0])

        except Exception as e:
            print("Shodan Error: %s" % e)

        try:
            for qu in censys_query_list:
                query = h.search(qu[1] + ip)
                results = query()

                if len(results) > 0:
                    infra_list.append(qu[0])

        except Exception as e:
            print("Censys Error: %s" % e)

        if len(infra_list) > 0:
            result_dict[ip] = infra_list
            print(ip, " : ", result_dict[ip])

    print("[Total result]")
    print(result_dict)

