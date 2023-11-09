# ML Tool for Cross-Platform Binary Analysis
![Ghidra](https://img.shields.io/badge/Ghidra-WinAPI-blue)
![YARA](https://img.shields.io/badge/YARA%20Rule-green)
![CAPA](https://img.shields.io/badge/TTP-CAPA-purple)

## Project Description
This project aims to create a machine learning model that can classify binary files into appropriate Command and Control (C2) types. The classification relies on five key features: Yara lists, TTP (Tactics, Techniques, and Procedures) lists, Windows API lists, and the number of nodes and edges in the Control Flow Graph extracted from binary files using Ghidra. Various classifiers such as Random Forest, XGBoost, LightGBM, Support Vector Classifier (SVC), CatBoost, etc., are trained using these five pieces of information. The project evaluates the performance of these classifiers to determine their effectiveness in classifying binary files.

## Overall Task
- [1. System Programming Recap]()
- [2. API : Shodan, Censys]()
- [3. Data Crawling]()
- [4. CFG extraction]()
- [5. Ghidra : Windows API]()
- [6. CAPA : TTP list]()
- [7. YARA list]()
- [8. Number of Nodes and Edges]()
- [9. Dataset Proprocessing]()
- [10. Machine Learning]()

## Dataset
There are a total of 436 binary files, and they belong to seven different C2 types. These C2 types are as follows: Cobaltstrike, Metasploit, Covenant, Bruteratel, Deimos, Sliver, and Posh. Please refer to the following table.

| C2 Type       | Number of Files |
|---------------|-----------------|
| Cobaltstrike  | 121             |
| Bruteratel    | 53              |
| Covenant      | 11              |
| Deimos        | 19              |
| Sliver        | 43              |
| Posh          | 14              |
| Metasploit    | 175             |

![Data Distribution](./data_distribution.png)

## Evaluation
![evaluation](./evaluation.png)
