from flask import Flask, render_template, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
import requests
import json
UPLOAD_FOLDER = '/tempfiles'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app = Flask(__name__, static_url_path="", static_folder="static")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

API_HOST = "http://10.0.0.128:8088"


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def main():
    return render_template("index.html")


@app.route("/upload")
def upload():
    uid = "0x4d409AB08C5B631A84dB907E4a916a7ea1375898"
    items = requests.get(API_HOST+"/v2/items/"+uid)

    return render_template("upload.html", API_HOST=API_HOST, items=items.json())


if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, port=80)
