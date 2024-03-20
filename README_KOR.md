# webshell_detector
파이썬을 이용한 웹쉘 파일 탐지기

## 프레임워크 및 사용 언어
- <img src="https://img.shields.io/badge/Framework-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/flask-000000?style=for-the-badge&logo=flask&logoColor=white">
- <img src="https://img.shields.io/badge/Language-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/python-3776AB?style=for-the-badge&logo=python&logoColor=white"> 
- <img src="https://img.shields.io/badge/Server-%23121011?style=for-the-badge">![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white)

## 필수 패키지
![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white)![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

## 실행 및 삭제

### 실행
1. `virus total`에 회원가입 후, API 키를 발급받는다.

2. `git clone https://github.com/greyhawk16/webshell_detector.git`를 실행하여, 현재 리포지토리를 로컬 환경으로 복사한다.

3. `deploy` 폴더에 `.ENV` 파일을 생성한다.

4. 앞서 얻은 API 키를 `.ENV`에 추가한다. 단, 이름은 `VIRUSTOTAL_API_KEY`로 지정한다.

5. `docker-compose.yaml`이 있는 폴더에서, `docker compose up -d`를 실행한다.

### 삭제
1. `docker-compose.yaml`이 있는 폴더에서, `docker compose down`을 실행한다.


## 비즈니스 로직

1. 분석하고 싶은 파일들을 업로드한다.

2. 업로드 한 파일들을 확인하는 URL `/file_upload`로 이동한다.

3. `/file_upload`에서 `Analyze` 버튼을 누르면, 분석을 시작한다.

4. `/analysis_result`에서 분석결과를 표 형식으로 화면에 표시한다.

5. 4의 `Download CSV` 버튼을 누르면, 분석 결과를 CSV 파일로 다운로드 할 수 있다.


## 판단 기준


## Planned Updates
1. Section의 메타데이터 분석

2. 파일의 IAT & EAT 정보 획득

3. 파일의 TLS 정보 파악

4. 파일의 헤더 정보 획득

5. 디지털 서명 여부 및 상세정보 획득

6. 파일의 엔트로피 계산


## 참고자료