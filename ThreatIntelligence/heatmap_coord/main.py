import argparse
import pandas as pd
import folium
import ipinfo
from folium.plugins import HeatMap
from APIKEY import APIKEY_IPINFO

api_key = APIKEY_IPINFO
api_handler = ipinfo.getHandler(api_key)

def calc_coor(ip_address):
	ips = [ip_address[x:x+100] for x in range(0, len(ip_address), 100)]
	
	coord_list = []	
	for ip in ips:
		bd = [x + "/loc" for x in ip]
		list_value = list(api_handler.getBatchDetails(bd).values())
		coord = [x.split(',') for x in list_value if not isinstance(x, dict)]
		coord_list.extend(coord)
	
	return coord_list


def heatmap(coord, filename):
	m = folium.Map(tiles="OpenStreetMap", location=[20,10], zoom_start=2)
	HeatMap(data=coord, radius=15, blur=20, max_zoom=2, max_val=2).add_to(m)
	m.save(filename) 
	print("Heatmap saved")  


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--input_file", default="ip.csv", type=str)
	parser.add_argument("--output_file", default="result.html", type=str)
	args = parser.parse_args()

	#df = pd.read_csv(args.input_file)
	ip_list = pd.read_csv(args.input_file)["IP"].values.tolist()
	coor = calc_coor(ip_list)
	heatmap(coor, args.output_file)


