import pandas as pd

result_file = "result.csv"

# CSV 파일을 읽어옵니다.
df = pd.read_csv(f'./Sliver/{result_file}')

# Family 열을 기준으로 Unknown 값을 카운트하기 위한 딕셔너리를 생성합니다.
singleton_count = {}
new_family_list = []

# 데이터를 순회하면서 처리합니다.
for index, row in df.iterrows():
    family = row['Family']
    family_dict = eval(family)  # 문자열을 딕셔너리로 변환합니다.

    # Family 값에서 SINGLETON:으로 시작하는 부분을 찾아 수정합니다.
    for key in list(family_dict.keys()):
        if key.startswith('SINGLETON:'):
            hash_value = key.split('SINGLETON:')[1]
            if hash_value in singleton_count:
                new_key = singleton_count[hash_value]
            else:
                new_key = f'Unknown{len(singleton_count) + 1}'
                singleton_count[hash_value] = new_key
            
            # 키 이름을 변경하고 딕셔너리 내에서 해당 키를 유지합니다.
            family_dict[new_key] = family_dict.pop(key)

    # 수정된 Family 값을 다시 문자열로 변환합니다.
    new_family = str(family_dict)
    new_family_list.append(new_family)

# 새로운 Family 값을 업데이트합니다.
df['Family'] = new_family_list

# 결과를 새로운 CSV 파일로 저장합니다.
df.to_csv(f'{result_file}', index=False)
