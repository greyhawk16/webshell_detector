import sys
import os
CMD = sys.argv[1]

if CMD == "deploy":
    API_KEY = sys.argv[2]
    f = open("./code/deploy/.ENV", "w")
    f.write(f"VIRUSTOTAL_API_KEY='{API_KEY}'")
    f.close()
    
    os.system("cd ./terraform; terraform init; terraform apply")

elif CMD == "destroy":
    os.system("cd ./terraform; terraform destroy")

else:
    print("Please choose between deploy, destroy")