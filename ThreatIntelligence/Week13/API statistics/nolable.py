import csv
import re

# CSV 파일에서 데이터 읽기
with open('./Sliver/result.csv', 'r', newline='') as csvfile:
    reader = csv.reader(csvfile)
    header = next(reader)  # 헤더 라인 읽기

    new_data = []
    for row in reader:
        function, dll, occurence, json_string, *optional_columns = row
        associated = optional_columns[-1] if optional_columns else ''

        # "Unknown" 키와 인덱스 추출
        unknown_data = re.findall(r"'Unknown(\d+)': (\d+)", json_string)
        
        # "nolabel" 키 추가
        json_data = {}
        nolabel_count = 0
        for index, value in unknown_data:
            nolabel_count += int(value)

        if nolabel_count > 0:
            json_data['nolabel'] = nolabel_count

        # 다른 키-값 쌍 유지
        for key, value in eval(json_string).items():
            if not key.startswith('Unknown'):
                json_data[key] = value

        # 새로운 데이터 행 생성
        new_row = [function, dll, occurence, str(json_data)]
        if associated:
            new_row.append(associated)

        new_data.append(new_row)

# 새로운 데이터를 CSV 파일로 쓰기
with open('result.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(header)  # 헤더 쓰기
    writer.writerows(new_data)  # 데이터 쓰기
