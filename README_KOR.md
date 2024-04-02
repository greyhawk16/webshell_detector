# webshell_detector

<img src="https://img.shields.io/badge/Language-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54"> 
<img src="https://img.shields.io/badge/Framework-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/flask-%23121011?style=for-the-badge&logo=flask&logoColor=white"> 
<img src="https://img.shields.io/badge/Server-%23121011?style=for-the-badge">![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white)

<img src="https://img.shields.io/badge/Container%20Platform-%23121011?style=for-the-badge">![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
<img src="https://img.shields.io/badge/Cloud%20Platform-%23121011?style=for-the-badge">![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
<img src="https://img.shields.io/badge/IAC-%23121011?style=for-the-badge">![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)

주어진 파일을 분석하고, 웹쉘인지 판단하는 웹서비스 입니다. 랜섬웨어 등의 기타 악성코드인 경우, 분석 결과에 `Other`로 표시합니다. 분석 결과는 CSV 형식으로 다운로드 할 수 있습니다.

English version [➡️](https://github.com/greyhawk16/webshell_detector/blob/main/README.md)

## 필수 패키지
<img src="https://img.shields.io/badge/OS-%23121011?style=for-the-badge">![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)![macOS](https://img.shields.io/badge/mac%20os-%23121011?style=for-the-badge&logo=macos&logoColor=F0F0F0)

<img src="https://img.shields.io/badge/Packages-%23121011?style=for-the-badge">![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white)
- Python [➡](https://www.python.org/downloads/)
- Terraform [➡](https://developer.hashicorp.com/terraform/install)
- AWS CLI [➡](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- GIT [➡](https://git-scm.com/downloads)


## 실행 및 삭제

### Run
1. [VirusTotal](https://www.virustotal.com/gui/home/upload) 에 회원 가입을 하고, API 키를 발급받습니다.

2. AWS에 회원가입한 다음, Access key와 Secret Access key를 발급 받습니다. 단, Secret Access key는 새로 발급받은 직후에만 다운받을 수 있습니다!

3. 명령창에서 `aws configure`를 실행하여, 기본 profile을 설정해줍니다. 아래 명령은 예시입니다.

```
    AWS Access Key ID [None]: YOUR_ACCESS_KEY
    AWS Secret Access Key [None]: YOUR_SECRET_ACCESS_KEY
    Default region name [None]: us-east-2
    Default output format [None]:
```

4. 아래의 명령을 실행해줍니다.

    ```
    git clone https://github.com/greyhawk16/webshell_detector.git
    cd ./webshell_detector
    python3 deployer.py deploy YOUR_VIRUSTOTAL_API_KEY
    ```
    위 명령은 VirusTotal에서 받은 API키를 저장하기 위한 `.ENV` 파일을 자동으로 생성해줍니다. 다음으로 Terraform을 이용하여 AWS EC2 인스턴스 1개(OS: `Ubuntu`) 생성하고, 새성한 EC2 인스턴스에서 웹서비스를 실행합니다.

### Delete

아래 명령을 실행하면 앞서 생성한 AWS 리소스를 자동적으로 삭제할 수 있습니다.

    ```
    cd ./webshell detector
    python3 deployer.py destroy
    ```

이 명령은 `.ENV`, `.pem` 등의 파일까지는 삭제하지 않습니다.  



## 비즈니스 로직

1. 분석하고 싶은 파일들을 업로드한다.

2. 업로드 한 파일들을 확인하는 URL `/file_upload`로 이동한다.

3. `/file_upload`에서 `Analyze` 버튼을 누르면, 분석을 시작한다.

4. `/analysis_result`에서 분석결과를 표 형식으로 화면에 표시한다.

5. 4의 `Download CSV` 버튼을 누르면, 분석 결과를 CSV 파일로 다운로드 할 수 있다.


## 판단 기준
1. 파일 확장자에 특수문자가 들어있는 지, 2개 이상의 확장자를 갖는 지 검사합니다.[1]

2. 웹쉘에 자주 사용되는 확장자(`php`, `jsp`, `asp`)를 가진 파일의 경우, 파일 속에 수상한 키워드(`system`, `shell_exec`, `eval`)가 들어있는 지 확인합니다.[2] [3]

3. 알려진 웹쉘의 해시값과, 주어진 파일의 해시값을 비교합니다.

4. 파일의 해시값이 VirusTotal 또는 MalwareBazaar에 웹쉘, 또는 기타 악성코드로서 등재되었는지 확인합니다.


## Planned Updates
1. 탐지 기능
    - Section의 메타데이터 분석

    - 파일의 IAT & EAT 정보 획득

    - 파일의 TLS 정보 파악

    - 파일의 헤더 정보를 획득하여, 악성코드 개발 환경 유추

    - 디지털 서명 여부 및 관련 정보 획득

    - 파일의 엔트로피 계산


2. 기타
    - `서버-클라이언트` 아키텍처 적용
    - 회원 가입 시, 분석 결과를 계정에 저장


## 참고자료
[1] https://www.igloo.co.kr/security-information/webshell-%ED%8C%A8%ED%84%B4-%EC%88%98%EC%A7%91-%EC%A0%90%EA%B2%80-%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8-%EC%8B%A4%ED%96%89-%EB%B0%8F-%EC%9C%A0%ED%98%95%EB%B3%84-%EB%B6%84%EC%84%9D%EB%B0%A9%EB%B2%95/

[2] https://redcanary.com/threat-detection-report/trends/webshells/ 

[3] https://github.com/thadriss/Webshell-Detect