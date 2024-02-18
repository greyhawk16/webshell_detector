# 원본: https://github.com/therealdriss/Webshell-Detect
# 현재: 확장자, 키워드 기반 탐지
# 추가기능: 
# V  1. 파일 확장자 내 특수문자 탐지 -> regex 활용
# V  2. csv 기록 시 파일의 생성일시 기록    
#    3. 웹쉘 키워드 확충
#    4. csv에 기록하는 내용 변경

# 추후 계획: 도커화


import os
import csv
import re


webshell_extensions = ['.php', '.asp', '.jsp'] # add any other extensions commonly used for webshells
webshell_keywords = ['system', 'shell_exec', 'eval'] # add any other keywords commonly used in webshells
SPECIAL_CHARACTER_DETECTION_PATTERN = re.compile(r'[^A-Za-z]')   # 파일 확장자는 알파벳 대소문자만 허용


# 1. 확장자 속 특수문자 파악
def check_special_character_in_file_extension(file_path):
    file_extension = os.path.splitext(file_path)[1]
    extension = file_extension[1:]

    if SPECIAL_CHARACTER_DETECTION_PATTERN.search(extension):  # 정규표현식으로 확장자 내 특수문자 파악
       print(file_path)
       return True
    else:
        return False


# 2. 여러 개의 확장자를 가진 파일 파악
def check_multiple_extensions_of_file(file_path):
    parsed_path = file_path.split('/')   # 경로 parse
    file_name = parsed_path[-1]  # 파일명
    file_name_and_extension = file_name.split('.')   # 파일명, 확장자 parse

    if len(file_name_and_extension) != 2:  # 확장자가 2개 이상, 또는 아예 없는 경우
        print(file_path)
        return True
    else:
        return False
    

    # 3. 의심가는 확장자 검사


# main 함수
def detect_webshell(root_dir):
    with open('webshell_detection_results.csv', mode='w') as csv_file:
        fieldnames = ['File Path', 'Keywords Found']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for root, _, files in os.walk(root_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_extension = os.path.splitext(file_path)[1]
                
                check_special_character_in_file_extension(file_path)
                check_multiple_extensions_of_file(file_path)

                if file_extension in webshell_extensions:  # 의심 확장자 포함 시
                    with open(file_path, 'r') as f:
                        file_contents = f.read()
                        keywords_found = []

                        for keyword in webshell_keywords:   
                            if keyword in file_contents:
                                keywords_found.append(keyword)

                        if keywords_found:
                            writer.writerow({'File Path': file_path, 'Keywords Found': keywords_found})
                            print('File Path', file_path, 'Keywords Found', keywords_found)


detect_webshell('./uploads') # specify the root directory of the web server
