from flask import Flask, render_template, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
import requests
import json
from cloudant.client import CouchDB

from util import security, forms

COUCH_USER = "admin"
COUCH_PASS = "Queef master 5000."
COUCH_URL = "http://10.0.0.128:5984"

client = CouchDB(COUCH_USER, COUCH_PASS, url=COUCH_URL, connect=True)
usersdb = client['users']

UPLOAD_FOLDER = '/tempfiles'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__, static_url_path="", static_folder="static")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "Super Secret -- use DB or something"

API_HOST = "http://10.0.0.128:8088"


# homepage
@app.route("/")
def main():
    return render_template("index.html")


# file storage page
@app.route("/upload")
def upload():
    uid = "0x4d409AB08C5B631A84dB907E4a916a7ea1375898"
    items = requests.get(API_HOST+"/v2/items/"+uid)

    return render_template("upload.html", API_HOST=API_HOST, items=items.json())


# user endpoint; POST creates new user, PUT updates password
@app.route("/user", methods=["POST", "PUT", "DELETE"])
def user():
    if (not request.json):
        return "PLEASE PROVIDE JSON"

    if (request.method == "POST"):
        return signupJSON()
    elif (request.method == "PUT"):
        return changePass()
    elif (request.method == "DELETE"):
        return deleteUser()


# login endpoint
@app.route("/login", methods=["POST"])
def login():
    if (not request.json):
        return "PLEASE PROVIDE JSON"

    email = request.json['email']
    password = request.json['password']

    if (checkCredentials(email, password)):
        return("SUCCESS")
    else:
        return("FAIL")


# registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if (request.method == "POST"):
        user = forms.register(request)
        if (user):
            # form is valid; sign 'em up
            result = signup(user.email, user.password)
            if (result == "OK"):
                return redirect("/")
            else:
                return result
        else:
            return "Registration Failed"
    else:
        return render_template("register.html")


# helper function; account deletion
def deleteUser():
    if (not request.json):
        return "PLEASE PROVIDE JSON"

    email = request.json['email']
    password = request.json['password']

    if (checkCredentials(email, password)):
        doc = usersdb[email]
        doc.delete()
        return "OK"
    else:
        return "INVALID CREDENTIALS"


# helper function: change password
def changePass():
    if (not request.json):
        return "PLEASE PROVIDE JSON"

    email = request.json['email']
    password = request.json['password']
    newPass = request.json['newPassword']

    if (checkCredentials(email, password)):
        doc = usersdb[email]
        doc['password'] = newPass
        doc.save()
        return "OK"
    else:
        return "INVALID CREDENTIALS"


# helper function; sign up new user
def signupJSON():
    if (not request.json):
        return "PLEASE PROVIDE JSON"

    email = request.json['email']
    password = request.json['password']

    return signup(email, password)


# helper function; sign up new user with form
def signup(email, password):
    # package data into dict
    data = {'_id': email, 'password': password}

    if (data['_id'] in usersdb):
        return "USER ALREADY EXISTS"

    # add user to DB
    doc = usersdb.create_document(data)

    if (doc.exists()):
        return "OK"
    else:
        return "DB ERROR"


# helper function; authenticate with DB
def checkCredentials(email, password):
    try:
        user = usersdb[email]
        if (password == user['password']):
            return True
        else:
            return False
    except KeyError as e:
        print(e)
        return False


# helper function
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, port=80)
