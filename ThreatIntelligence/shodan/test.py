from shodan import Shodan

ips = ['175.126.109.15', '104.18.32.68', '8.8.8.8', '162.0.217.254', '52.109.12.19',
           '20.189.173.2', '209.197.3.8', '94.130.174.62', '192.124.249.36', '149.154.167.99',
           '187.212.199.121', '211.229.47.232', '58.235.189.192', '40.126.32.69', '20.72.205.209',
           '93.184.220.29', '52.152.108.96', '162.0.217.254', '52.242.101.226', '8.238.110.126',
           '52.140.118.28', '94.130.174.62', '192.124.249.22', '172.64.155.188', '149.154.167.99',
           '51.104.136.2', '52.109.12.18', '192.124.249.41', '87.248.202.1', '175.126.109.15',
           '104.18.32.68', '20.189.173.3', '162.0.217.254', '211.171.233.126', '94.130.174.62',
           '172.64.155.188', '149.154.167.99', '52.109.12.18', '178.79.208.1', '15.197.142.173', '192.195.77.147',
           '93.184.220.29', '198.49.23.145', '93.184.221.240', '104.110.191.182', '198.1.95.93', '23.2.164.159',
           '198.185.159.144', '8.238.20.126', '37.75.50.246', '162.0.217.254', '151.251.30.69',
           '20.189.173.14', '94.130.174.62', '192.124.249.22', '172.64.155.188', '149.154.167.99', '142.250.179.142',
           '138.148.98.222', '147.170.231.243', '152.136.251.149', '101.245.162.180', '24.94.37.103', '65.235.220.3',
           '205.36.240.171', '138.90.140.217', '122.14.62.84', '30.2.81.153', '106.231.152.17', '79.184.52.39',
           '184.92.124.254', '55.54.187.175', '26.83.65.198', '153.169.16.33', '20.21.169.20', '7.163.183.39',
           '32.134.138.201', '61.103.73.79', '123.194.132.19', '185.253.147.202', '34.94.248.21', '89.189.11.223',
           '153.221.47.97', '195.146.222.236', '114.86.71.73', '102.24.84.248', '130.6.22.191', '203.114.31.14',
           '192.89.92.125', '194.200.13.75', '217.24.153.51', '96.121.88.181', '159.104.88.118', '133.163.89.63',
           '168.232.151.235', '54.182.180.234', '160.125.77.110', '40.46.165.100', '37.157.116.245', '144.206.240.232',
           '203.76.185.22', '113.184.110.108', '195.132.116.96', '95.151.230.161', '142.17.255.112', '140.84.59.16',
           '177.5.17.231', '200.100.104.189', '205.23.245.179', '157.122.4.146', '182.70.221.209', '208.178.139.130',
           '19.27.114.91', '66.31.74.4', '73.204.238.175', '185.43.184.200', '68.223.140.138', '162.122.27.195',
           '182.212.45.238', '144.102.4.136', '19.190.124.210', '44.141.55.255', '180.3.5.248', '194.136.170.138',
           '20.182.55.34', '106.129.180.235', '201.215.95.210', '195.123.141.153', '13.110.120.170', '184.12.19.147',
           '26.198.96.28', '136.205.33.7', '105.182.220.43', '60.153.7.236', '73.214.229.31', '66.231.13.61', '39.75.94.130',
           '200.145.165.3', '60.116.78.236', '103.142.40.157', '137.221.9.35', '91.76.73.186', '131.195.140.64', '90.101.243.137',
           '150.134.60.227', '197.104.7.104', '114.11.167.171', '145.131.225.74', '198.166.201.128', '97.95.122.69',
           '173.205.136.191', '82.140.149.165', '34.117.59.81', '152.199.19.160']
#api = Shodan("0DvKU6VjSCMZGR45FlS5aCA7Xqn9wWsR")
api = Shodan("G6GMcp1wYvbXKbSfWYooxQbCgENDtMBz")

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