import csv
import json
import argparse
import folium
import pandas as pd

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file1", default="country-codes-tlds.csv", type=str)
    parser.add_argument("--input_file2", default="country_dns.csv", type=str)
    parser.add_argument("--output_file", default="result.csv", type=str)
    args = parser.parse_args()

    # country_code to dict
    c_code_dict = list()
    with open(args.input_file1, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            c_code_dict.append(row)

    # country_dns to dict
    c_dns_dict = list()
    with open(args.input_file2, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            c_dns_dict.append(row)

    # For csv
    result_list = [
        ["country", "tld", "count"]
    ]

    # For heatmap
    result_dict = dict()
    tld_list = list()
    count_list = list()

    # Search
    for c_code in c_code_dict:
        tld = c_code[" tld"].split(".")[1]
        result = [c_code["country"], tld]

        for c_dns in c_dns_dict:
            if c_dns.get("tld") == tld:
                result.append(c_dns.get("Count"))
                tld_list.append(tld.upper())
                count_list.append(int(c_dns.get("Count")))

        # Add to result_list for generating CSV
        result_list.append(result)

    # Folium Heatmap config
    geo_path = "World_Countries__Generalized_.geojson"
    geo_data = json.load(open(geo_path, encoding="UTF-8"))
    tld_inf = pd.DataFrame(data=tld_list, columns=["tld"])
    cnt_inf = pd.DataFrame(data=count_list, columns=["count"])
    map_data = pd.concat([tld_inf, cnt_inf], axis=1)

    m = folium.Map(location=[37.63772494531694, 24.785517601541628], zoom_start=2,
                   max_bounds=True,
                   min_zoom=2, min_lat=-84,
                   max_lat=84, min_lon=-175, max_lon=187)

    folium.Choropleth(geo_data=geo_data,
                      data=map_data,
                      columns=["tld", "count"], key_on="properties.ISO",
                      highlight=True,
                      fill_color='RdYlGn', fill_opacity=0.7, line_opacity=0.5).add_to(m)


    m.save("result.html")

    """
    # Generate CSV
    with open(args.output_file, mode='w', newline='', encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(result_list)
    """
