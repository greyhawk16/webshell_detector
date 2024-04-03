# Webshell_detector

<img src="https://img.shields.io/badge/Language-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54"> 
<img src="https://img.shields.io/badge/Framework-%23121011?style=for-the-badge"><img src="https://img.shields.io/badge/flask-%23121011?style=for-the-badge&logo=flask&logoColor=white"> 
<img src="https://img.shields.io/badge/Server-%23121011?style=for-the-badge">![Nginx](https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white)

<img src="https://img.shields.io/badge/Container%20Platform-%23121011?style=for-the-badge">![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
<img src="https://img.shields.io/badge/Cloud%20Platform-%23121011?style=for-the-badge">![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
<img src="https://img.shields.io/badge/IAC-%23121011?style=for-the-badge">![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)

This web application analyzes a given file and determines if it's webshell or not. When given other types of malware(ransomware, etc.), displays the result as `Other``. After analysis, can download the analysis result in a CSV file. 


Korean version [➡️](https://github.com/greyhawk16/webshell_detector/blob/main/README_KOR.md)


## Requirements
<img src="https://img.shields.io/badge/OS-%23121011?style=for-the-badge">![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)![macOS](https://img.shields.io/badge/mac%20os-%23121011?style=for-the-badge&logo=macos&logoColor=F0F0F0)

<img src="https://img.shields.io/badge/Packages-%23121011?style=for-the-badge">![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white)
- Python [➡](https://www.python.org/downloads/)
- Terraform [➡](https://developer.hashicorp.com/terraform/install)
- AWS CLI [➡](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- GIT [➡](https://git-scm.com/downloads)

## Run or Delete

### Run
1. Join [VirusTotal](https://www.virustotal.com/gui/home/upload) to get API key. 

2. Join AWS and get an access key. Make sure you save both `ACCESS KEY` and `SECRET ACCESS KEY`. You can store or see `SECRET ACCESS KEY` ONLY when you just created the access key.

3. Run `aws configure` to configure the default profile for AWS-CLI. Below is an example.


        AWS Access Key ID [None]: YOUR_ACCESS_KEY
        AWS Secret Access Key [None]: YOUR_SECRET_ACCESS_KEY
        Default region name [None]: us-east-2
        Default output format [None]:



4. Run below commands.
It will create `.ENV` file to store your API key from VirusTotal, 1 AWS EC2 instance for hosting this web application, and 2 docker containers running on the EC2 instance.
    ```
    git clone https://github.com/greyhawk16/webshell_detector.git
    cd ./webshell_detector
    python3 deployer.py deploy YOUR_VIRUSTOTAL_API_KEY
    ```

### Delete
Run `python3 deployer.py destroy` command to stop and delete this web service along with related resources.


## Business Logic

1. Upload files you want to analyze.
After uploading, go to `/file_upload`.

3. Push the `Analyze` button to start the analysis.

4. `/analysis_result` will show the analysis result in table format.

5. Click the `Download CSV` button to download results as a CSV file.


## Standards used in the detection
Check if a special character is present in the file's extension, or comes with more than 1 extension.[1]

2. For files with extestions commonly used for webshell(`php`, `jsp`, `asp`), determine if it contains more than 1 suspicious keywords(`system`, `shell_exec`, `eval`).[2]
[3]

3. Check the file's hash value to the known webshell's hash value.

4. Send queries to VirusTotal and MalwareBazaar to check hash value(`SHA256`) of the given file is registered as webshell or other types of malware. It will show `True` if the hash is registered as webshell, and `Other` when the hash is registered but not as webshell. `False` if the hash is not found.

A file that satisfies at least one standard above, is considered a webshell and will be included in the analysis result. Even if a file is found to be other types of malware, this will add the file to the analysis result.

## Planned Updates
1. Detection features
    - Analyze the Section's metadata

    - Get information related to the target file's IAT & EAT

    - Check TLS info. of given file
    - Obtain the header of a given file to speculate the malware developer's environment

    - Check digital certification
    - Calculate a file's entropy to determine if the file has been packed

2. Others
    - Implement `Server-Client` structure
    - Allow users to join, log in and store analysis results in their accounts.

## References
[1] https://www.igloo.co.kr/security-information/webshell-%ED%8C%A8%ED%84%B4-%EC%88%98%EC%A7%91-%EC%A0%90%EA%B2%80-%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8-%EC%8B%A4%ED%96%89-%EB%B0%8F-%EC%9C%A0%ED%98%95%EB%B3%84-%EB%B6%84%EC%84%9D%EB%B0%A9%EB%B2%95/

[2] https://redcanary.com/threat-detection-report/trends/webshells/ 

[3] https://github.com/thadriss/Webshell-Detect