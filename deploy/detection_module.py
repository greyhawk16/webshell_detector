"""
    원본: https://github.com/therealdriss/Webshell-Detect

    추가기능: 
    - regex를 활용하여 파일 확장자 내 특수문자 탐지 
    - 여러 개의 확장자를 가지는지 파악
    - 보유중인 웹쉘의 해시값과, 파일의 해시값 비교
    - 파일의 해시값이 VirusTotal, MalwareBazaar에서 악성코드로 분류되는 지 파악
    - csv에 탐지된 파일 이름, 절대경로, 생성일시, 탐지 사유 기록

    추후 계획: 도커화

    웹쉘 해시값 리스트: https://github.com/greyhawk16/sfiles_yara/blob/master/hacktools/web_shells.yara

    사용예정 API
    - VirusTotalAPI
    - MalwareBazaar(https://bazaar.abuse.ch/api/)
"""


import os
import csv
import re
import platform
import requests
import json
import hashlib

from dotenv import load_dotenv

# target_directory = input('Enter target directory: ')
load_dotenv()


class subject:                                               # 검사한 파일의 정보를 저장하는 class
    def __init__(self) -> None:
        self.file_path = './'                                # 파일 경로
        self.sha256_hash = ''
        self.special_character_in_file_extension = False     # 확장자 속 특수문자 포함 여부
        self.multiple_extensions = False                     # 여러 확장자를 가지는 지 여부
        self.suspicious_extensions_with_keywords = False     # 의심가는 확장자이고, 웹쉘로 판단할 수 있는 키워드를 포함하는 지
        self.match_webshell_hash = False                   # 보유한 웹쉘 해시값 중 한 개와 일치하는 지
        self.found_at_virus_total = False                    # VirusTotal에 웹쉘 또는 기타 악성코드로 등록되어 있는 지
        self.found_at_malware_bazaar = False                 # MalwareBazaar 에 웹쉘 또는 그 외 악성코드로 등록되어 있는 지  


# 1. 확장자 속 특수문자 파악
def check_special_character_in_file_extension(file_path):
    SPECIAL_CHARACTER_DETECTION_PATTERN = re.compile(r'[^A-Za-z]')  # 알파벳 대소문자 외의 문자가 존재하는 지 파악

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
    webshell_extensions = ['.php', '.asp', '.jsp'] # add any other extensions commonly used for webshells
    webshell_keywords = ['system', 'shell_exec', 'eval'] # add any other keywords commonly used in webshells
    file_extension = os.path.splitext(file_path)[1]

    if file_extension in webshell_extensions:  # 의심 확장자 포함 시
        with open(file_path, 'r') as f:
            file_contents = f.read()
            keywords_found = []

            for keyword in webshell_keywords:   
                if keyword in file_contents:
                     keywords_found.append(keyword)

                if keywords_found:  # 의심가는 확장자의 파일 중, 웹쉘로 판단될 키워드 포함 시 -> 웹쉘로 판단
                    return True     
            else:
                return False
            

# 4. 현재 보유한 웹쉘의 SHA256 해시값 중, 주어진 파일의 해시값이 존재하는 지 판별
def check_stored_hash(file_path):
    HASH_LIST = set({
        'f9fea823076f5a68fffea0eedc761e258a463b411a7364cf1abb5ab0f5f82024',
        'f318db10e2536fdab7c1799d90113d3f837325dc896713135ed5d6f30f035dab',
        'e9b35b391d248775771d0690adc9eb63c70892cc3c09526101ec97dbe79232d7',
    })  # 알려진 웹쉘들의 해시값을 모아둔 set

    f = open(file_path, 'rb')
    data = f.read()
    f.close()
    file_hash = hashlib.sha256(data).hexdigest() 

    if file_hash in HASH_LIST:  # 해시값이 웹쉘의 해시값 중 하나와 같다면 -> 웹쉘로 판단
        return True             
    else:
        return False


# 5. virustotal에 파일해시값 업로드 후 웹쉘인지 판별
def check_hash_via_virus_total(file_path):
    f = open(file_path, 'rb')
    data = f.read()
    f.close()
    file_hash = hashlib.sha256(data).hexdigest()                             

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    resp_content = json.loads(response.text)  
    
    if response.status_code == 200:  
        try:                                             # file_hash가 virusotal에 등록된 경우
            res = resp_content['data']['attributes']['crowdsourced_yara_results']     # 악성코드에 해당되는 기준
            
            for r in res:                    # 해당되는 기준 순회
                tmp = r['rule_name']         # 기준 이름
                if 'webshell' in tmp:        # 기준 이름에 'webshell' 단어 포함 시 -> 웹쉘로 판단
                    return 'webshell'   
        except:
            return 'other'                   # 웹쉘이 아닌 다른 악성코드인 경우, 'other' 반환
    
    else:
        return False                     # 404 응답을 받은 경우 -> 악성코드로 판단하지 않음


# 6. 파일 해시값이 MalwareBazaar에 악성코드로 분류되었는지 판단
def check_hash_via_malware_bazaar(file_path):
    f = open(file_path, 'rb')
    data = f.read()
    f.close()
    file_hash = hashlib.sha256(data).hexdigest()              # file_path 에 있는 파일의 SHA256 해시값

    data = {'query': 'get_info', 'hash': file_hash}
    url = "https://mb-api.abuse.ch/api/v1/"
    response = requests.post(url, data=data)

    if response.json()["query_status"] != 'hash_not_found':   # 악성코드의 해시값과 일치할 경우
        response_json = response.json()["data"][0]

        tag_list = response_json['tags']     # 악성코드의 태그 정보
        print(tag_list)
        tag_list = set(tag_list)             # 시간복잡도 향상을 위해, set으로 변환

        if 'webshell' in tag_list:           # 해당 악성코드의 대크에 'webshell'이 있다면 
            return 'webshell'                # 웹쉘로 판단
        else:
            return 'others'                  # 웹쉘이 아닌 다른 악성코드로 판단
    else:
        return False                         # 악성코드가 아닌 파일로 판단


# 웹쉘로 분류된 파일의 정보, 분류 사유를 csv에 적는 함수
def write_csv(suspect_paths):
    CSV_FILE_NAME = 'webshell_detection_results.csv'
    with open(CSV_FILE_NAME, mode='w') as csv_file:
        field_names = ['File Name', 
                       'File Path', 
                       'Created At', 
                       'SHA256 hash',
                       'Special character in extension', 
                       'Multiple file extensions', 
                       'Suspicious keyword present',
                       'Match known hash',
                       'VirusTotal says',
                       'MalwareBazaar says'
                       ]
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()

        for row in suspect_paths:
            tmp = row.file_path              
            file_name = tmp.split('/')[-1]   # 파일 이름
            abs_path = os.path.abspath(tmp)  # file_path를 절대 경로로 변환
            
            # OS 별 파일 생성일시를 파악하는 방법에 차이 존재
            if platform.system == 'Windows':
                created_at = os.path.getctime(abs_path)
            else:
                created_at = os.stat(abs_path).st_birthtime

            temp = {
                'File Name': file_name,
                'File Path': abs_path,
                'Created At': created_at,
                'SHA256 hash': row.sha256_hash,
                'Special character in extension': row.special_character_in_file_extension,
                'Multiple file extensions': row.multiple_extensions,
                'Suspicious keyword present': row.suspicious_extensions_with_keywords,
                'Match known hash': row.match_webshell_hash,
                'VirusTotal says': row.found_at_virus_total,
                'MalwareBazaar says': row.found_at_malware_bazaar
            }   # CSV에 적을 행
            
            writer.writerow(temp)
        return CSV_FILE_NAME


# main 함수
def detect_webshell(root_dir):
    suspect_paths = []   # 웹쉘로 분류된 파일 경로 저장

    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)

            row = subject()  # 현재 보고있는 파일의 이름, 웹쉘로 판단한 근거를 저장
            row.file_path = file_path

            f = open(file_path, 'rb')
            data = f.read()
            f.close()
            row.sha256_hash = hashlib.sha256(data).hexdigest()

            if check_special_character_in_file_extension(file_path):  # 확장자 속 특수문자 존재 여부 검증
                row.special_character_in_file_extension = True
            if check_multiple_extensions_of_file(file_path):  # 여러 개의 확장자를 가지는 지 검증
                row.multiple_extensions = True
            if check_suspicious_extensions(file_path):  # 의심가는 확장자를 가진 파일 중, 웹쉘로 판단될 만한 키워드를 포함하고 있는 지 검증
                row.suspicious_extensions_with_keywords = True
            if check_stored_hash(file_path):
                row.match_webshell_hash = True
            
            row.found_at_virus_total = check_hash_via_virus_total(file_path)
            row.found_at_malware_bazaar = check_hash_via_malware_bazaar(file_path)

            if (
                row.special_character_in_file_extension or
                row.multiple_extensions or
                row.suspicious_extensions_with_keywords or
                row.found_at_virus_total != False or
                row.found_at_malware_bazaar != False
            ):  # 위의 5개 기준 중 하나 이상 해당하는 경우 
                suspect_paths.append(row)   # 웹쉘로 판단, 기록
    
    res = write_csv(suspect_paths)
    return res


# target_directory = "./uploads"
# x = detect_webshell(target_directory) # specify the root directory of the web server
# print(x)
