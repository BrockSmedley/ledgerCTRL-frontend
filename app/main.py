from flask import Flask, render_template, flash, request, redirect, url_for, abort, Response, send_file
from werkzeug.utils import secure_filename
from werkzeug.wsgi import wrap_file
import requests
import json
import sys
import os
import pyqrcode
import datetime
import shutil
from cloudant.client import CouchDB
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_uploads import *
from util import security, forms
from util import user as User


login_manager = LoginManager()

COUCH_USER = "admin"
COUCH_PASS = "Queef master 5000."
COUCH_URL = "http://172.16.66.4:5984"

client = CouchDB(COUCH_USER, COUCH_PASS, url=COUCH_URL, connect=True)
usersdb = client['users']

UPLOAD_FOLDER = '/tempfiles'

API_HOST = "http://172.16.66.2:8088/v2/"
LOCAL_HOST = "ctrl.vaasd.com/"

app = Flask(__name__, static_url_path="", static_folder="static")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "Super Secret -- use DB or something"
patch_request_class(app, 128*1024*1024)  # max file size: 128 MB
login_manager.init_app(app)


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
    # URL to use in the QR code
    data = LOCAL_HOST + "scan/" + itemhash
    pyqrcode.create(data).png(fname, scale=5)
    fstream.close()
    fstream = open(fname, "rb")
    return send_file(fstream, mimetype="image/png")


# inventory proxy
@app.route("/inventory", methods=["POST"])
@login_required
def inventory():
    # TODO: un-proxy request; save file locally & send via requests.post()
    fileup = request.files['upfile']
    item = request.form['inventoryItem']
    userIndex = request.form['userIndex']
    public = request.form['public']
    if (public == 'public'):
        public = True
    else:
        public = False

    # generate secure filename for upfile
    sfn = secure_filename(fileup.filename)
    # save file locally
    fileup.save(sfn)

    # pack up request data to forward to API_HOST
    jdata = {'inventoryItem': item, 'userIndex': userIndex, 'public': public}
    f_u = {'upfile': open(sfn, 'rb')}

    # send request to API_HOST
    res = requests.post(API_HOST + "inventory",
                        files=f_u, data=jdata)

    # return error code or refresh on success
    if (res.status_code != 200):
        return res.text
    return redirect("/upload")


# inventory item proxy
@app.route("/inventory/<item>", methods=["GET"])
@login_required
def inventoryItem(item):
    return getItem(item)


def getItem(itemhash):
    res = requests.get(API_HOST+"inventory/%s" % itemhash)
    return res.json()


def itempageTemplate(itemhash, fileItem, name, owner=None):
    scansReq = requests.get(API_HOST+"scans/"+itemhash)
    scans = scansReq.json()

    txReq = requests.get(API_HOST + "transfers/" + itemhash)
    transfers = txReq.json()

    return render_template("item.jinja",
                           filename=fileItem['Name'],
                           filehash=fileItem['Hash'],
                           itemhash=itemhash,
                           title=name,
                           scans=scans,
                           transfers=transfers,
                           current_user=current_user,
                           owner=owner)


@app.route("/item/<itemhash>", methods=["GET"])
def itempage(itemhash):
    res = getItem(itemhash)
    fileItem = res['fileHash']
    name = res['inventoryItem']['name']
    public = res['public']
    owner = res['inventoryItem']['owner']

    if (not public):
        if hasattr(current_user, "email") and current_user.email == owner:
            return itempageTemplate(itemhash, fileItem, name, owner)
        else:
            return render_template("sowwy.jinja", title="Rekt")
    else:
        return itempageTemplate(itemhash, fileItem, name, owner)


# file proxy
@app.route("/file/<hash>")
@login_required
def file(hash):
    # get filename from API
    url = API_HOST + "inventory/%s" % hash
    res = requests.get(url)
    jdata = res.json()
    filename = jdata['fileHash']['Name']
    print(filename)

    # get raw file from API
    url = API_HOST + "file/%s" % hash
    res = requests.get(url, stream=True)

    # read out file to local tempfile
    with open('temp', 'wb') as out_file:
        shutil.copyfileobj(res.raw, out_file)
    del res

    # send it
    return send_file('temp', as_attachment=True, attachment_filename=filename)


# smart tag scan
@app.route("/scan/<hash>")
def scanTag(hash):
    if (hasattr(current_user, "email")):
        cdata = {
            "user": current_user.email,
            "date": str(datetime.datetime.now())
        }
        jdata = {"itemId": str(hash), "scanData": json.dumps(cdata)}
        tx = requests.post(API_HOST+"scan", json=jdata)
        txid = tx.json()
        return render_template("scan.jinja", title="scan", txid=txid)
    else:
        return render_template("sowwy.jinja", title="Sup anon")


# transfer page
@app.route("/transfer/<itemhash>", methods=["GET"])
@login_required
def transfer(itemhash):
    item = getItem(itemhash)
    return render_template("transfer.jinja", title="Transfer Item", itemhash=itemhash, item=item, current_user=current_user)


@app.route("/transfer", methods=["POST"])
@login_required
def transfer_item():
    data = request.form
    itemhash = data['itemhash']
    newOwnerEmail = data['email']

    user = usersdb[current_user.email]
    newOwner = usersdb[newOwnerEmail]

    jdata = {
        "userIndex": int(user['eth_index']),
        "userPass": user['eth_password'],
        "itemhash": itemhash,
        "newOwnerIndex": int(newOwner['eth_index']),
        "newOwner": newOwnerEmail
    }

    res = requests.post(API_HOST+"transfer", json=jdata)

    txhash = (res.text).replace('"', '')

    return render_template("success.jinja", newOwner=newOwnerEmail, txHash=txhash)


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
    # epass = randomPass()
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
