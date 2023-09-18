import csv
import json
import datetime
import shodan
from APIKEY import APIKEY_SHODAN2

idx = 0
api = shodan.Shodan(APIKEY_SHODAN2)
date_domain_list = ["Last Analysis Date", "Last Update Date", "Creation Date", "Last Http Certificate Date", "Last Dns Records Date"]

# Read CSV
with open("ReportTable.csv", newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    data = [row for row in reader]

# Iterate data
for datum in data:
    domain = datum["Domain Name"]                                                           # Domain name
    date_list = list()

    for date_domain in date_domain_list:                                                    # Iterate dates in CSV
        if datum[date_domain] is None or datum[date_domain] == "":
            continue

        date_start = datum[date_domain].split(" ")[0]
        year = int(date_start.split("-")[0])
        month = int(date_start.split("-")[1])
        day = int(date_start.split("-")[2])
        #date_end = datetime.datetime(year, month + 3, day).strftime('%Y-%m-%d')            # Calculate day by date_start + 1
        date_end = datetime.datetime(year, (month + 3) % 12 + 1, day).strftime('%Y-%m-%d')  # Calculate day by date_month + 3
        query = "hostname:{} after:{} before:{}".format(domain, date_start, date_end)       # Shodan Query String

        # Dictionary to save in JSON
        result = dict()

        try:
            result[date_start] = api.search(query)
            print(domain, date_start, date_end, " Results found : {}".format(result[date_start]["total"]))
            print(result[date_start]["matches"])
        except shodan.APIError as e:
            print("Error: {}".format(e))

    #with open(domain + ".json", "w") as f:
    #    json.dump(result, f)

    idx += 1
    if idx > 2:
        pass
        #break

