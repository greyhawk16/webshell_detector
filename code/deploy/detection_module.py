"""
    참고한 코드: https://github.com/therealdriss/Webshell-Detect

    추가기능: 
    - regex를 활용하여 파일 확장자 내 특수문자 탐지 
    - 여러 개의 확장자를 가지는지 파악
    - 보유중인 웹쉘의 해시값과, 파일의 해시값 비교
    - 파일의 해시값이 VirusTotal, MalwareBazaar에서 악성코드로 분류되는 지 파악
    - csv에 탐지된 파일 이름, 절대경로, 생성일시, 탐지 사유 기록

    사용한 API
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
import pefile
import collections
import math

from dotenv import load_dotenv


load_dotenv()


class subject:                                               # 검사한 파일의 정보를 저장하는 class
    def __init__(self) -> None:
        self.file_path = './'                                # 파일 경로
        self.sha256_hash = ''
        self.special_character_in_file_extension = False     # 확장자 속 특수문자 포함 여부
        self.multiple_extensions = False                     # 여러 확장자를 가지는 지 여부
        self.suspicious_extensions_with_keywords = False     # 의심가는 확장자이고, 웹쉘로 판단할 수 있는 키워드를 포함하는 지
        self.match_known_webshell_hash = False                     # 보유한 웹쉘 해시값 중 한 개와 일치하는 지
        self.found_at_virus_total = False                    # VirusTotal에 웹쉘 또는 기타 악성코드로 등록되어 있는 지
        self.found_at_malware_bazaar = False                 # MalwareBazaar 에 웹쉘 또는 그 외 악성코드로 등록되어 있는 지
        self.file_entropy = 0                                # 파일의 엔트로피(범위: 0 이상 & 8이하) 계산, 7 이상 -> 악성코드로 간주
        self.rich_header_key = None
        self.rich_header_records = None


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
    webshell_extensions = ['.php', '.asp', '.jsp'] 
    webshell_keywords = ['system', 'shell_exec', 'eval']
    file_extension = os.path.splitext(file_path)[1]

    if file_extension in webshell_extensions:  # 의심 확장자 포함 시
        with open(file_path, 'r') as f:
            file_contents = f.read()
            keywords_found = []

            for keyword in webshell_keywords:   
                if keyword in file_contents:
                     keywords_found.append(keyword)

                if keywords_found:  # 웹쉘로 판단될 키워드 포함 시 -> 웹쉘로 판단
                    return True     
            else:
                return False
            

# 4. 현재 보유한 웹쉘의 SHA256 해시값 중, 주어진 파일의 해시값이 존재하는 지 판별
def check_stored_hash(file_hash):
    HASH_LIST = set({
        'f9fea823076f5a68fffea0eedc761e258a463b411a7364cf1abb5ab0f5f82024',
        'f318db10e2536fdab7c1799d90113d3f837325dc896713135ed5d6f30f035dab',
        'e9b35b391d248775771d0690adc9eb63c70892cc3c09526101ec97dbe79232d7',
    })  # 알려진 웹쉘들의 해시값을 모아둔 set

    if file_hash in HASH_LIST:  # 해시값이 웹쉘의 해시값 중 하나와 같다면 -> 웹쉘로 판단
        return True             
    else:
        return False


# 5. virustotal에 파일해시값 업로드 후 웹쉘인지 판별
def check_hash_via_virus_total(file_hash):    
    API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    API_URL = os.getenv("VIRUSTOTAL_API_URL")

    url = f"{API_URL}/{file_hash}"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
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
            else:
                return 'Other'
        except:
            return 'Other'                   # 웹쉘이 아닌 다른 악성코드인 경우, 'Other' 반환
    else:
        return False                     # 404 응답을 받은 경우 -> 악성코드로 판단하지 않음


# 6. 파일 해시값이 MalwareBazaar에 악성코드로 분류되었는지 판단
def check_hash_via_malware_bazaar(file_hash):

    data = {'query': 'get_info', 'hash': file_hash}
    url = "https://mb-api.abuse.ch/api/v1/"
    response = requests.post(url, data=data)

    try: 
        if response.json()["query_status"] != 'hash_not_found':   # 악성코드의 해시값과 일치할 경우
            response_json = response.json()["data"][0]

            tag_list = response_json['tags']     # 악성코드의 태그 정보
            print(tag_list)
            tag_list = set(tag_list)             # 시간복잡도 향상을 위해, set으로 변환

            if 'webshell' in tag_list:           # 해당 악성코드의 대크에 'webshell'이 있다면 
                return 'webshell'                # 웹쉘로 판단
            else:
                return 'Other'                  # 웹쉘이 아닌 다른 악성코드로 판단
        else:
            return False                         # 악성코드가 아닌 파일로 판단
    except:
        return False
    


# 엔트로피를 이용하는 함수
def check_entropy(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    byte_cnt = collections.Counter(data)
    file_length = len(data)

    entropy = 0

    for cnt in byte_cnt.values():
        p = cnt / file_length
        
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy

# exe 대상, 악성코드 개발자 환경 추측: Rich header 사용
def get_rich_header(file_path):
    # return : [Key, Records여부]

    ans = {
        'key': 'None',
        'records': 'None'
    }

    try:
        pe = pefile.PE(file_path)
        rich_header = pe.parse_rich_header()

        if rich_header != None:
            print(f"Key: {rich_header['key']}")
            ans['key'] = rich_header['key']

            if 'records' in rich_header:
                records = rich_header['records']
                ans['records'] = records 
    
    except Exception as e:
        ans = {
        'key': 'Not PEfile',
        'records': 'Not PEfile'
    }

    return ans


# 악성코드 내 디지털 서명 여부 판별 및 상세정보 획득
def get_certification_info(file_path):
    cert_entry = None
    return cert_entry


# IAT, EAT 정보
def get_iat_eat(file_path):
    iat_eat_info = None
    return iat_eat_info


# section이 지닌 메타데이터 정보 획득
def get_section_info(file_path):
    section_info = None
    return section_info


# 웹쉘로 분류된 파일의 정보, 분류 사유를 csv에 적는 함수
def write_csv(suspect_paths):

    CSV_FILE_NAME = 'webshell_detection_results.csv'

    with open(CSV_FILE_NAME, mode='w') as csv_file:
        field_names = ['File Name', 
                       'File Path', 
                       'Examined At', 
                       'SHA256 hash',
                       'Special character in extension', 
                       'Multiple file extensions', 
                       'Suspicious keyword present',
                       'Match known hash',
                       'Result from VirusTotal',
                       'Result from MalwareBazaar',
                       'Shannon Entropy',
                       'Rich header Key',
                       'Rich header Records'
                       ]
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()

        for row in suspect_paths:
            tmp = row.file_path              
            file_name = tmp.split('/')[-1]   # 파일 이름
            abs_path = os.path.abspath(tmp)  # file_path를 절대 경로로 변환
            
            # OS 별 파일 생성일시를 파악하는 방법에 차이 존재
            created_at = os.path.getctime(abs_path)

            result = [
                file_name,
                abs_path,
                created_at,
                row.sha256_hash,
                row.special_character_in_file_extension,
                row.multiple_extensions,
                row.suspicious_extensions_with_keywords,
                row.match_known_webshell_hash,
                row.found_at_virus_total,
                row.found_at_malware_bazaar,
                row.file_entropy,
                row.rich_header_key,
                row.rich_header_records
            ]

            temp = dict()

            for i in range(len(field_names)):
                key = field_names[i]
                dat = result[i]
                temp[key] = dat


            # temp = {
            #     'File Name': file_name,
            #     'File Path': abs_path,
            #     'Examined At': created_at,
            #     'SHA256 hash': row.sha256_hash,
            #     'Special character in extension': row.special_character_in_file_extension,
            #     'Multiple file extensions': row.multiple_extensions,
            #     'Suspicious keyword present': row.suspicious_extensions_with_keywords,
            #     'Match known hash': row.match_known_webshell_hash,
            #     'Result from VirusTotal': row.found_at_virus_total,
            #     'Result from MalwareBazaar': row.found_at_malware_bazaar,
            #     'Shannon Entropy': row.file_entropy,
            #     'Rich header Key': row.rich_header_key,
            #     'Rich header Records present': row.rich_header_records
            # }   # CSV에 적을 행
            
            writer.writerow(temp)
        return CSV_FILE_NAME


# main 함수
def detect_webshell(root_dir):
    suspect_paths = []   # 웹쉘로 분류된 파일 경로 저장

    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)

            row = subject()  # 현재 보고있는 파일의 이름, 경로, 분석 결과를 저장
            row.file_path = file_path

            f = open(file_path, 'rb')
            data = f.read()
            f.close()
            row.sha256_hash = hashlib.sha256(data).hexdigest()

            if check_special_character_in_file_extension(file_path):  
                row.special_character_in_file_extension = True

            if check_multiple_extensions_of_file(file_path):  
                row.multiple_extensions = True

            if check_suspicious_extensions(file_path):  
                row.suspicious_extensions_with_keywords = True

            if check_stored_hash(row.sha256_hash):
                row.match_known_webshell_hash = True
            
            row.found_at_virus_total = check_hash_via_virus_total(row.sha256_hash)
            row.found_at_malware_bazaar = check_hash_via_malware_bazaar(row.sha256_hash)
            row.file_entropy = check_entropy(row.file_path)
            
            rich_header_info = get_rich_header(row.file_path)
            row.rich_header_key = rich_header_info['key']
            row.rich_header_records = rich_header_info['records']

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