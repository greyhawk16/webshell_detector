FROM python:3.13-rc-alpine3.19
WORKDIR /root
ADD main.py .
CMD ["python3", "main.py"]