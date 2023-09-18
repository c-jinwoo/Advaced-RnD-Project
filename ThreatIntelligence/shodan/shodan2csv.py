import pandas as pd
import os
from shodan import Shodan
from APIKEY import APIKEY_SHODAN2

api = Shodan(APIKEY_SHODAN2)
list_ip = []
list_domain = []
list_port = []
list_country = []
list_city = []
list_vulns = []

# Settings
rows = 0
max_rows = 200
search_query = "Apache"
file_name = "shodanCSV.csv"

# Extract information using API
for result in api.search(search_query, page=3)["matches"]:
    try:
        result_ip = result["ip_str"]                        # IP with dot
        result_domain = result["domains"]                   # List of Domains
        result_port = result["port"]                        # Current using Port
        result_location = result["location"]                # Location includes country name, country code, city
        result_vulns = result["vulns"]                      # Vulnerability in CVE list

        list_ip.append(result_ip)
        list_domain.append(result_domain)
        list_port.append(result_port)
        list_country.append(result_location["country_name"])
        list_city.append(result_location["city"])
        list_vulns.append(list(result_vulns.keys()))

        rows += 1
        if rows >= max_rows:
            break
    except:
        pass

# Convert to CSV
data = {
    "IP" : list_ip,
    "Domain" : list_domain,
    "Port" : list_port,
    "Country" : list_country,
    "City" : list_city,
    "Vulns" : list_vulns
}
df = pd.DataFrame(data)
if not os.path.exists(file_name):
    df.to_csv(file_name, index=False, mode="w")
else:
    df.to_csv(file_name, index=False, mode="a")

print(df)

