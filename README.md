# ML Tool for Cross-Platform Binary Analysis
![Ghidra](https://img.shields.io/badge/Ghidra-WinAPI-blue)
![YARA](https://img.shields.io/badge/YARA%20Rule-green)
![CAPA](https://img.shields.io/badge/TTP-CAPA-purple)

## Project Description
This project aims to create a machine learning model that can classify binary files into appropriate Command and Control (C2) types. The classification relies on five key features: Yara lists, TTP (Tactics, Techniques, and Procedures) lists, Windows API lists, and the number of nodes and edges in the Control Flow Graph extracted from binary files using Ghidra. Various classifiers such as Random Forest, XGBoost, LightGBM, Support Vector Classifier (SVC), CatBoost, etc., are trained using these five pieces of information. The project evaluates the performance of these classifiers to determine their effectiveness in classifying binary files.

## Project Duration
2023.03 ~ 2023.11

## Requirements
```
$ pip install tqdm
$ pip install catboost
```

## Overall Task
- [1. System Programming Recap](https://github.com/c-jinwoo/skku_grad_proj/tree/master/1.%20System%20Programming%20Recap)
- [2. API : Shodan, Censys](https://github.com/c-jinwoo/skku_grad_proj/tree/master/2.%20API)
- [3. Data Crawling](https://github.com/c-jinwoo/skku_grad_proj/tree/master/3.%20Dataset%20Crawling)
- [4. CFG extraction](https://github.com/c-jinwoo/skku_grad_proj/tree/master/4.%20CFG)
- [5. Ghidra : Windows API](https://github.com/c-jinwoo/skku_grad_proj/tree/master/5.%20Windows%20API)
- [6. CAPA : TTP list](https://github.com/c-jinwoo/skku_grad_proj/tree/master/6.%20TTP)
- [7. YARA list](https://github.com/c-jinwoo/skku_grad_proj/tree/master/7.%20YARA)
- [8. Number of Nodes and Edges](https://github.com/c-jinwoo/skku_grad_proj/tree/master/8.%20Dataset%20Organizing)
- [9. Dataset Proprocessing](https://github.com/c-jinwoo/skku_grad_proj/tree/master/9.%20Word%20Embedding)
- [10. Machine Learning](https://github.com/c-jinwoo/skku_grad_proj/blob/master/c2_ml_final.ipynb)

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

### Word Embedding

To match train data length, word embedding is used for TTP, YARA, and Windows API elements. The whole list elements are put into one single string while passing through the [preprossesing for word embedding](https://github.com/c-jinwoo/skku_grad_proj/tree/master/9.%20Word%20Embedding) , then later splitted into the list with dimension of 256 by Word2Vec model.
```
model = Word2Vec(unbalanced_dataset["data"], vector_size=256, window=5, min_count=1, sg=0, callbacks=[epoch_logger])
model.save("word2vec.model")
```

### Imputation

If there are samples with no possible list with TTP, YARA, or Windows API, those went through imputation with the mean value from the others.

```
imputer = SimpleImputer(strategy="mean")
unbalanced_dataset = pd.DataFrame(imputer.fit_transform(unbalanced_dataset), columns=unbalanced_dataset.columns)
```

### Balancing

The number of files are balanced to 50 samples equally. For Cobaltstrike, Bruteratel, and Metasploit, they went through down-sampling while the other four C2 types went through up-sampling to make 50 samples per each. Upsampling is done by using SMOTE, while downsampling is done by resample() from sklearn. As a result, the overall dataset became 350, 50 samples for every type of C2.

```
# Upsampling
X = balanced_dataset.drop(["label"], axis=1)
y = balanced_dataset["label"]

oversample = SMOTE()
X_res, y_res = oversample.fit_resample(X, y)

balanced_dataset = X_res[:]
balanced_dataset["label"] = y_res

balanced_dataset.shape

# Downsampling
def resample_df(df, number_samples):
    from sklearn.utils import resample
    return resample(df, n_samples=number_samples, replace=False, random_state=0)
```

## Evaluation
The overall Accuracy, Precision, Recall, and F1 score were around from 0.81 to 0.85. However, for SVC, it had relatively low performance compare to the other classifiers:Random Forest, XGB, LGBM, and Catboost.

![evaluation](./evaluation.png)
