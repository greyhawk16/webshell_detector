# 메인 flask 앱
import os

from flask import Flask, flash, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
from detection_functions import *


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "uploads/"


# 참고자료: https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
@app.route('/file_upload', methods = ['GET', 'POST'])
def upload_file():    # 시작 화면, 파일 업로드
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No files detected')
            return redirect([request.url])
        
        else:
            files = request.files.getlist('file')

            for file in files:
                file_name = file.filename
                file.save(app.config['UPLOAD_FOLDER'] + file_name)
                # 파일 이름에 특수문자 포함 시, 서비스 거부

            return render_template("upload_result.html", name=files)
    else:
        return render_template("index.html")


@app.route('/uploaded_file_list', methods = ['GET'])
def uploaded_files_dashboard():
    files = os.listdir("./uploads")
    return render_template('uploaded_file_list.html', files=files)


@app.route("/analysis_result", methods = ['GET'])
def display_analysis_result():
    return render_template('analysis_result.html')


@app.route('/')
def home():
    return render_template("index.html")


if __name__=='__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)