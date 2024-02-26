FROM python:3.13.0a4-alpine3.19
WORKDIR /root
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY main.py main.py
CMD ["python3", "main.py"]