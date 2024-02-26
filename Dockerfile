FROM ubuntu:latest

RUN apt update
RUN apt install python3 -y
RUN apt install pip3 -y
RUN pip3 install -r requirements.txt

WORKDIR /usr/app/src
COPY main.py .
CMD ["python3", "main.py"]