from censys.search import CensysHosts
from censys.search import SearchClient
from censys.search import CensysCertificates

h = CensysHosts()
s = SearchClient()
c = CensysCertificates

# Single page of search results
#query = h.search("service.service_name: HTTP", per_page=5)
query = h.search("services.http.response.body_hash='sha1:b18d778b4e4b6bf1fd5b2d790c941270145a6a6d'")
results = query()
for result in results:
    print(result["ip"])
#print("Query : ", query())
print("============================================")

"""
host = h.view("8.8.8.8")
print("Host : ", host)
print("============================================")

# The aggregate method constructs a report using a query, an aggregation field, and the
# number of buckets to bin.
report = s.v2.hosts.aggregate(
    "service.service_name: HTTP",
    "services.port",
    num_buckets=5,
)
print("Aggregate : ", report)
print("============================================")

# Fetch metadata about hosts.
meta = h.metadata()
print("Metadata : ", meta)
print("============================================")

# Fetch a list of host names for the specified IP address.
names = h.view_host_names("1.1.1.1")
print("View Host Names : ", names)
print("============================================")

# View specific certificate
cert = c.view("a762bf68f167f6fbdf2ab00fdefeb8b96f91335ad6b483b482dfd42c179be076")
print("Certificate View : ", cert)
print("============================================")
"""