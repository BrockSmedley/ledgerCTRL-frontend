from flask import Flask, render_template, flash, request, redirect, url_for, abort, Response, send_file
from werkzeug.utils import secure_filename
import requests
import json
import sys
import os
import pyqrcode
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

app = Flask(__name__, static_url_path="", static_folder="static")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "Super Secret -- use DB or something"
login_manager.init_app(app)

API_HOST = "http://172.16.66.2:8088/v2/"
LOCAL_HOST = "10.0.0.128:8099/"


@login_manager.user_loader
def load_user(user_id):
    try:
        user = usersdb[user_id]
        password = user['password']

        u = User.User(user_id, password)
        return u
    except KeyError as e:
        print(e)
        print("Could not find user.")
        return None


def _proxy(request, append=""):
    resp = requests.request(
        method=request.method,
        url=request.url.replace('http://localhost/', API_HOST + append),
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
    return render_template("index.jinja", title="Dashboard", current_user=current_user)


# file storage page
@app.route("/upload")
def upload():
    # if user is logged in, fetch their files
    items = None
    jitems = {}
    uid = ""
    upass = ""
    try:
        if (current_user.email):
            # get user index
            user = usersdb[current_user.email]
            uid = str(user['eth_index'])
            upass = user['eth_password']

            # get items from ETH
            items = requests.get(API_HOST+"items/"+uid)
            if (items.json()):
                jitems = items.json()
    except AttributeError:
        print("Anonymous user detected.")

    print(jitems)

    return render_template("upload.jinja", items=jitems, title="Asset Vault", current_user=current_user, uid=uid, upass=upass)


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
        return render_template('login.jinja', title="Log In")
    else:
        return render_template('login.jinja', title="Log In")


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
        return render_template("register.jinja", title="New Account", current_user=current_user)


# create QR code from itemhash
@app.route("/tag/<itemhash>", methods=["GET"])
def getTag(itemhash):
    fname = itemhash+'.png'
    fstream = open(fname, "wb")
    data = LOCAL_HOST + "item/" + itemhash
    pyqrcode.create(data).png(fname, scale=5)
    fstream.close()
    fstream = open(fname, "rb")
    return send_file(fstream, mimetype="image/png")


# inventory proxy
@app.route("/inventory", methods=["POST"])
@login_required
def inventory():
    res = _proxy(request)
    return redirect("/upload")


# inventory item proxy
@app.route("/inventory/<item>", methods=["GET"])
@login_required
def inventoryItem(item):
    return _proxy(request)


def getItem(itemhash):
    res = requests.get(API_HOST+"inventory/%s" % itemhash)
    return res.json()


@app.route("/item/<itemhash>", methods=["GET"])
def itempage(itemhash):
    res = getItem(itemhash)
    fileItem = res['fileHash']
    name = res['name']

    if current_user.email == res['owner']:
        return render_template("item.jinja", name=name,
                               filename=fileItem['Name'],
                               filehash=fileItem['Hash'],
                               itemhash=itemhash,
                               title="Asset Manager",
                               current_user=current_user)
    else:
        return render_template("sowwy.jinja", title="Rekt")


# file proxy
@app.route("/file/<hash>")
@login_required
def file(hash):
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


def randomPass():
    pbytes = os.urandom(48)
    o = []
    for b in pbytes:
        r = b % 64
        o.append(r)
    return("".join(map(chr, pbytes)))


# helper function; sign up new user with form
def signup(email, password):
    # package data into dict
    data = {'_id': email, 'password': password}

    print("USER INFO: %s" % str(data))

    if (data['_id'] in usersdb):
        return "USER ALREADY EXISTS"

    # generate random password for ETH account
    #epass = randomPass()
    epass = "TODO: FIX RANDOM PASS GENERATOR"

    # create new ETH account
    rdata = {"password": epass}
    account = requests.post(API_HOST+"ethUser", json=rdata)
    account = account.json()

    # add account index to DB datapage
    data['eth_index'] = account['index']
    data['eth_password'] = epass
    print(data)

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


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False, port=80)
