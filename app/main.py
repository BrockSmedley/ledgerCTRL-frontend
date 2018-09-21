from flask import Flask, render_template, flash, request, redirect, url_for, abort, Response
from werkzeug.utils import secure_filename
import requests
import json
import sys
from cloudant.client import CouchDB
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from util import security, forms
from util import user as User

login_manager = LoginManager()

COUCH_USER = "admin"
COUCH_PASS = "Queef master 5000."
COUCH_URL = "http://172.16.66.4:5984"

client = CouchDB(COUCH_USER, COUCH_PASS, url=COUCH_URL, connect=True)
usersdb = client['users']

UPLOAD_FOLDER = '/tempfiles'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__, static_url_path="", static_folder="static")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "Super Secret -- use DB or something"
login_manager.init_app(app)

API_HOST = "http://172.16.66.2:8088/v2"


@login_manager.user_loader
def load_user(user_id):
    user = usersdb[user_id]
    password = user['password']

    u = User.User(user_id, password)
    return u


def _proxy(request, append=""):
    resp = requests.request(
        method=request.method,
        url=request.url.replace('http://localhost', API_HOST + append),
        headers={key: value for (key, value)
                 in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding',
                        'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response


# homepage
@app.route("/")
def main():
    return render_template("index.html", title="Dashboard", current_user=current_user)


# file storage page
@app.route("/upload")
def upload():
    # if user is logged in, fetch their files
    items = None
    jitems = {}
    uid = ""
    print(current_user, file=sys.stderr)
    try:
        if (current_user.email):
            # get user's itembase address
            print(current_user.email)
            user = usersdb[current_user.email]
            uid = user['itembase']

            # get items from ETH
            items = requests.get(API_HOST+"/items/"+uid)
            if (items.json()):
                jitems = items.json()
    except AttributeError:
        print("Anonymous user detected.")

    return render_template("upload.html", API_HOST=API_HOST, items=jitems, title="Vault", current_user=current_user, itembase=uid)


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
@app.route("/login", methods=["POST", "GET"])
def login():
    if (request.method == "POST"):
        # verify valid input syntax
        user = forms.validateUser(request)

        # confirmed good login syntax
        if (user and checkCredentials(user.email, user.password)):
            login_user(user)

            next = request.args.get('next')
            if (not forms.is_safe_url(next)):
                return abort(400)
            return redirect(next or '/')
        return render_template('login.html', title="Log In")
    else:
        return render_template('login.html', title="Log In")


# logout endpoint
@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect("/")


# registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    if (request.method == "POST"):
        user = forms.validateRegistration(request)
        if (user):
            # form is valid; sign 'em up
            result = signup(user.email, user.password)
            if (result == "OK"):
                login_user(user)
                return redirect("/")
            else:
                return result
        else:
            return redirect('/register')
    else:
        return render_template("register.html", title="New Account", current_user=current_user)


# inventory proxy
@app.route("/inventory", methods=["POST"])
def inventory():
    return _proxy(request)


# inventory item proxy
@app.route("/inventory/<item>")
def inventoryItem(item):
    return _proxy(request)


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

    # get new itembase address from API
    itembase = requests.post(
        API_HOST+"/itembase", json={"userId": "0xcb39f9322b21150833303453ec20aabef0817f90"})
    addr = itembase.json()
    data['itembase'] = addr

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
