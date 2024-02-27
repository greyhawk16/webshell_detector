# 메인 flask 앱
import os

from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = './uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# 참고자료: https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
@app.route('/')
def upload_file():    # 시작 화면, 파일 업로드
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No files detected')
            return redirect([request.url])
        
        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            file_name = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
            return redirect(url_for)
        
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''