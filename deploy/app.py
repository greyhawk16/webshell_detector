# 메인 flask 앱
import os

from flask import Flask, flash, request, redirect, render_template, send_file
from detection_module import *


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

            files = os.listdir(app.config['UPLOAD_FOLDER'])
            return render_template('uploaded_file_list.html', files=files)
            # return render_template("upload_result.html", name=files)       # upload_result.html은 미사용
    else:
        return render_template("index.html")


# @app.route('/uploaded_file_list', methods = ['GET'])
# def uploaded_files_dashboard():
#     # files = os.listdir("./uploads")
#     files = os.listdir(app.config['UPLOAD_FOLDER'])
#     return render_template('uploaded_file_list.html', files=files)


@app.route("/analysis_result", methods = ['GET'])
def display_analysis_result():
    result_file = detect_webshell(app.config['UPLOAD_FOLDER'])
    with open(result_file) as file:
        reader = csv.reader(file)
        return render_template('analysis_result.html', csv=reader)
    

@app.route("/download_result", methods = ['GET'])
def download_analysis_result():
    # 분석결과를 담은 CSV 파일을 다운로드
    result_file = 'webshell_detection_results.csv'
    return send_file(result_file, as_attachment=True)


@app.route('/')
def home():
    return render_template("index.html")


if __name__=='__main__':
    app.run(host='0.0.0.0', port=os.environ.get("FLASK_SERVER_PORT", 9090), debug=True)