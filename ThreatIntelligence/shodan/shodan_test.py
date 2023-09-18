from shodan import Shodan
from APIKEY import APIKEY_SHODAN

api = Shodan(APIKEY_SHODAN)

"""
# Check if the site has a vulnerability with CVE list
cvelist = "cve-2014-0160"
results = api.search("has_vuln:"+cvelist, page=1)
#results = api.search("vuln:"+cvelist, page=1)          #only available to academic users
idx = 0
for result in results["matches"]:
    try:
        print(result)
        idx += 1
        if idx > 0:
            break
    except:
        pass
"""

idx = 0
search_query = "Apache"
results = api.search(search_query, page=1)
for result in results["matches"]:
    print("====================================================================================")
    try:
        result_ip = result["ip"]
        result_port = result["port"]
        result_location = result["location"]
        result_vulns = list(result["vulns"].keys())[0]

        print("IP : ", result_ip)
        print("PORT : ", result_port)
        print("COUNTRY_CODE : ", result_location["country_code"])
        print("COUNTRY_NAME : ", result_location["country_name"])
        print("CITY : ", result_location["city"])
        print("VULNS : ", result_vulns)

        idx += 1
        if idx > 5:
            break
    except:
        print("Not Available")

    #print(result["vulns"])
    #first_key = list(result["vulns"].keys())[0]
    #print(first_key)
"""
idx = 0
for ip in ips:
    if idx < 5:
        print("====================================================================================")
        try:
            ipinfo = api.host(ip)
            print("IP : ", ip)
            print("Port : ", ipinfo["ports"])
            print("Host Name : ", ipinfo["hostnames"])
            print("Country code : ", ipinfo["country_code"])
            print("Country name : ", ipinfo["country_name"])
            print("City : ", ipinfo["city"])
            print("Overall Data :")
            print(ipinfo["data"])
        except:
            print("No information on ", ip)

        idx += 1
"""




########################################################################################################################20230316
"""
# Lookup an IP
ipinfo = api.host("52.152.108.96")
print(ipinfo)
print(ipinfo["hostnames"])
#print("ipinfo.keys : ", ipinfo.keys())                         # Data columns
#print("ipinfo.ports : ", ipinfo["ports"])                      # Host's port info
#print("ipinfo.hostnames : ", ipinfo["hostnames"])              # Host info
#print("search = ", api.search("apache country:DE", page=1))
#print("tag:ics = ", api.count("tag:ics"))
#print(api.search_facets())
#print(api.search_filters())
#print(api.search_tokens("apache country:DE"))
#print(api.ports())
#print(api.protocols())
#print(api.queries(1, "votes", "asc"))
#print(api.queries())
"""

# Search page with condition
"""
def shodan_search(cnt_do):
    search_admin = api.search("admin", page=cnt_do)
    for item in search_admin['matches']:
        #print(item['location']['country_name'])
        if item['location']['country_name'] == "Korea, Republic of":
        # if item['port'] == 80:
            result_search = item['ip_str']
            return result_search

for cnt_do in range(1,3):
    result_search = shodan_search(cnt_do)
    print ("--------- Result on page %d --------" % cnt_do)

    if result_search is not None:
        print (result_search)
"""


"""
# Search for websites that have been "hacked"
# Requires upgraded API
for banner in api.search_cursor('http.title:"hacked by"', minify=False, retries=False):
    print(banner)
"""



"""
# Get the total number of industrial control systems services on the Internet
# Requires upgraded API
ics_services = api.count('tag:ics')
print('Industrial Control Systems: {}'.format(ics_services['total']))
"""