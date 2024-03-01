# 메인 flask 앱
import os

from flask import Flask, flash, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "uploads/"


# 참고자료: https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
@app.route('/fileUpload', methods = ['GET', 'POST'])
def upload_file():    # 시작 화면, 파일 업로드
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No files detected')
            return redirect([request.url])
        
        f = request.files['file']

        if f.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if f:
            file_name = f.filename
            f.save(app.config['UPLOAD_FOLDER'] + file_name)
            return render_template("upload_result.html", name=file_name)
    else:
        return render_template("index.html")
        


@app.route('/analysis_result', methods = ['GET'])
def display_analysis_result():
    return render_template('analysis_result.html')


@app.route('/')
def home():
    return render_template("index.html")


if __name__=='__main__':
    app.run(host='0.0.0.0', port=8088, debug=True)