FROM python:3.13.0a4-alpine3.19

COPY /deploy /app
WORKDIR /app

RUN pip3 install -r requirements.txt
EXPOSE 8088

CMD ["python3", "app.py"]