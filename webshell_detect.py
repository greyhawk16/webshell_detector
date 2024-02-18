# 원본: https://github.com/therealdriss/Webshell-Detect
# 현재: 확장자, 키워드 기반 탐지
# 추가기능: 
# V  1. 파일 확장자 내 특수문자 탐지 -> regex 활용
# V  2. csv 기록 시 파일의 생성일시 기록    
# V  3. 웹쉘 키워드 확충
# V  4. csv에 기록하는 내용 변경

# 추후 계획: 도커화


import os
import csv
import re
import datetime
import platform


webshell_extensions = ['.php', '.asp', '.jsp'] # add any other extensions commonly used for webshells
webshell_keywords = ['system', 'shell_exec', 'eval'] # add any other keywords commonly used in webshells
SPECIAL_CHARACTER_DETECTION_PATTERN = re.compile(r'[^A-Za-z]')   # 파일 확장자는 알파벳 대소문자만 허용


# 1. 확장자 속 특수문자 파악
def check_special_character_in_file_extension(file_path):
    file_extension = os.path.splitext(file_path)[1]
    extension = file_extension[1:]

    if SPECIAL_CHARACTER_DETECTION_PATTERN.search(extension):  # 정규표현식으로 확장자 내 특수문자 파악
       return True
    else:
        return False


# 2. 여러 개의 확장자를 가진 파일 파악
def check_multiple_extensions_of_file(file_path):
    file_name = file_path.split('/')[-1]   # 파일명
    file_name_and_extension = file_name.split('.')   # 파일명, 확장자 parse

    if len(file_name_and_extension) != 2:  # 확장자가 2개 이상, 또는 아예 없는 경우
        return True
    else:
        return False
    

# 3. 의심가는 확장자 검사
def check_suspicious_extensions(file_path):
    file_extension = os.path.splitext(file_path)[1]

    if file_extension in webshell_extensions:  # 의심 확장자 포함 시
        with open(file_path, 'r') as f:
            file_contents = f.read()
            keywords_found = []

            for keyword in webshell_keywords:   
                if keyword in file_contents:
                     keywords_found.append(keyword)

                if keywords_found:
                    return True
            else:
                return False
            

# 웹쉘로 분류된 파일의 정보, 분류 사유를 csv에 적는 함수
def write_csv(suspect_paths):
    with open('webshell_detection_results.csv', mode='w') as csv_file:
        field_names = ['File Name', 'File Path', 'Created At', 'Special character in extension', 'Multiple file extensions', 'Suspicious keyword present']
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()

        for row in suspect_paths:
            file_name = row[0].split('/')[-1]   # 경로 parse
            abs_path = os.path.abspath(row[0])
            
            # OS 별 파일 생성일시를 파악하는 방법에 차이 존재
            if platform.system == 'Windows':
                created_at = os.path.getctime(abs_path)
            else:
                created_at = os.stat(abs_path).st_birthtime

            temp = {
                'File Name': file_name,
                'File Path': abs_path,
                'Created At': created_at,
                'Special character in extension': 'X',
                'Multiple file extensions': 'X',
                'Suspicious keyword present': 'X'
            }

            if row[1]:
                temp['Special character in extension'] = 'O'
            if row[2]:
                temp['Multiple file extensions'] = 'O'
            if row[3]:
                temp['Suspicious keyword present'] = 'O'
            
            writer.writerow(temp)
            print(temp)

    return True


# main 함수
def detect_webshell(root_dir):
    suspect_paths = []   # 웹쉘로 분류된 파일 경로 저장


    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            row = [file_path, False, False, False]  # row[1]: 확장자 속 특수문자 여부, row[2]: 여러 확장자를 가지는지 여부, row[3]: 의심가는 확장자의 파일이 수상한 키워드를 포함하는 지

            if check_special_character_in_file_extension(file_path):
                row[1] = True
            if check_multiple_extensions_of_file(file_path):
                row[2] = True
            if check_suspicious_extensions(file_path):
                row[3] = True

            for i in range(1, 4):
                if row[i]:
                    suspect_paths.append(row)
                    break
    
    write_csv(suspect_paths)


detect_webshell('./uploads') # specify the root directory of the web server
