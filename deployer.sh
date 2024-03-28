# 용도: 배포에 필요한 명령들을 한번에 실행
# 실행 방법: ./deployer.sh YOUR_VIRUSTOTAL_API_KEY

# Write YOUR_VIRUSTOTAL_API_KEY to ./code/deploy/.ENV file
API_KEY=$1
touch ./code/deploy/.ENV
echo "VIRUSTOTAL_API_KEY='$API_KEY'" > ./code/deploy/.ENV

# run terraform
cd ./terraform
terraform init
terraform apply