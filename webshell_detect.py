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
find_special_character = re.compile(r'[^A-Za-z]')   # 파일 확장자는 알파벳 대소문자만 허용


def detect_webshell(root_dir):
    with open('webshell_detection_results.csv', mode='w') as csv_file:
        fieldnames = ['File Path', 'Keywords Found']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for root, dirs, files in os.walk(root_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_extension = os.path.splitext(file_path)[1]
                
                a = file_extension[1:]  # 확장자 앞 . 제거
                if find_special_character.search(a):  # 정규표현식 기반, 확장자 내 특수문자 파악
                    print(a)
                
                b = file_path[1:]  # 맨 앞의 . 제거
                b1 = b.split('/')  # / 로 string 분할
                b2 = b1[-1]   #  파일명
                b3 = b2.split('.')   # 파일명, 확장자 parse
                if len(b3) > 2:   # 확장자의 개수가 2개 이상 -> 웹쉘 파일로 취급
                    print(b)


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
