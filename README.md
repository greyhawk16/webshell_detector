# Webshell_detector
Webshell detection, analysis service using `flask`

Korean version [->](https://github.com/greyhawk16/webshell_detector/blob/main/README_KOR.md)

## Framework, Language, Web server
- <img src="https://img.shields.io/badge/Framework-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/flask-000000?style=for-the-badge&logo=flask&logoColor=white">
- <img src="https://img.shields.io/badge/Language-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/python-3776AB?style=for-the-badge&logo=python&logoColor=white"> 
- <img src="https://img.shields.io/badge/Server-%23121011?style=for-the-badge">![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white)

## Requirements
![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white)![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

## Run or Delete

### Run
1. Join `virus total` to get API key. 

2. Run `git clone https://github.com/greyhawk16/webshell_detector.git`

3. Create `.ENV` file in `deploy` directory.

4. Write your virus total API key to `.ENV`. Specify it's name as `VIRUSTOTAL_API_KEY`.

5. Run `docker compose up -d` in this directory to run this web service.

### Delete
1. Run `docker compose down` to stop and delete this web service.


## Business Logic

1. Upload files you want to analyze.

2. After upload, go to `/file_upload`.

3. Push `Analyze` button to start analysis.

4. `/analysis_result` will show analysis result in table format.

5. Click `Download CSV` button to download results as CSV file.


## Standards used in detection


## Planned Updates
1. Analyze Section's metadata

2. Get information related to target file's IAT & EAT

3. Check TLS info. of given file

4. Obtain header of given file to speculate malware developer's environment

5. Check digital certification

6. Calculate entropy of file to determine if file has been packed


## References
[] https://www.igloo.co.kr/security-information/webshell-%ED%8C%A8%ED%84%B4-%EC%88%98%EC%A7%91-%EC%A0%90%EA%B2%80-%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8-%EC%8B%A4%ED%96%89-%EB%B0%8F-%EC%9C%A0%ED%98%95%EB%B3%84-%EB%B6%84%EC%84%9D%EB%B0%A9%EB%B2%95/