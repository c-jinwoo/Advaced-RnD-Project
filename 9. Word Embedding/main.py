import os
import re
import ast
import csv
import argparse
import pandas as pd

original_dataset_path = "./dataset/original"                # Original Data
combined_dataset_path = "./dataset/combined/result.csv"     # Combined Data
stringfied_dataset_path = "./dataset/stringfied/result.csv" # Stringfied Data for Word Embedding

def combine():
    combined_df = pd.DataFrame()

    for filename in os.listdir(original_dataset_path):
        if filename.endswith(".csv"):
            file_path = os.path.join(original_dataset_path, filename)            
            df = pd.read_csv(file_path)

            # Select removing Hash and Firt time submission
            df = df[["TTP List", "YARA List", "API List", "Number of Nodes", "Number of Edges", "Type of C2"]]      

            # Replace column name
            df.rename(columns={"Number of Nodes": "node"}, inplace=True)       
            df.rename(columns={"Number of Edges": "edge"}, inplace=True)       
            df.rename(columns={"Type of C2": "label"}, inplace=True)        
            
            dataset_label = {
                "CobaltStrike": 0,
                "BruteRatel": 1,
                "Covenant": 2,
                "Deimos": 3,
                "Sliver": 4,
                "Posh": 5,
                "MetaSploit": 6
            }

            # Mapping with label and concatenate
            df["label"] = df["label"].map(dataset_label)
            combined_df = pd.concat([combined_df, df], ignore_index=True)

    combined_df.to_csv(combined_dataset_path, index=False)


def stringfy():
    #header = ["index", "data", "node", "edge", "label"]
    header = ["data", "node", "edge", "label"]

    with open(stringfied_dataset_path, 'w', newline='') as output_file:
        csv_writer = csv.writer(output_file)
        csv_writer.writerow(header)

        with open(combined_dataset_path, 'r', newline='') as file:
            csv_reader = csv.reader(file)
            next(csv_reader)            

            index = 0

            for row in csv_reader:
                index += 1
                ttp_data = ast.literal_eval(row[0]) if row[1] else []
                yara_data = ast.literal_eval(row[1]) if row[2] else []
                api_data = ast.literal_eval(row[2]) if row[3] else []
                node_data = row[3]
                edge_data = row[4]
                label_data = row[5]
                list_data = ""

                if len(ttp_data) > 0:
                    list_data += f"{ttp_data} "
                if len(yara_data) > 0:
                    list_data += f"{yara_data} "
                if len(api_data) > 0:
                    list_data += f"{api_data}"

                list_data = re.sub(r'[,"\'\[\]]', '', list_data)
                output_data = [ list_data.strip(), node_data, edge_data, label_data]
                
                csv_writer.writerow(output_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="combine", type=str)
    args = parser.parse_args()

    if args.mode == "combine":
        combine()
    elif args.mode == "stringfy":
        stringfy()

