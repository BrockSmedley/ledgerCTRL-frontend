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
import secrets
from cloudant.client import CouchDB
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_uploads import patch_request_class
from flask_mail import Message, Mail
from util import security, forms
from util import user as User


login_manager = LoginManager()

COUCH_USER = "admin"
COUCH_PASS = "Queef master 5000."
COUCH_URL = "http://172.16.66.4:5984"

client = CouchDB(COUCH_USER, COUCH_PASS, url=COUCH_URL, connect=True)
usersdb = client['users']
codesdb = client['codes']

UPLOAD_FOLDER = '/tempfiles'

API_HOST = "http://172.16.66.2:8088/v2/"
LOCAL_HOST = "10.0.0.129/"

app = Flask(__name__, static_url_path="", static_folder="static")
mail = Mail(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = "Super Secret -- TODO: use local file"

app.config['MAIL_SERVER'] = '172.16.66.7'
#app.config['MAIL_USERNAME'] = 'winston'
#app.config['MAIL_PASSWORD'] = 'smoke'
app.config['MAIL_DEFAULT_SENDER'] = 'winston@jeeves'

mail.init_app(app)

patch_request_class(app, 128*1024*1024)  # max file size: 128 MB
login_manager.init_app(app)

# TODO: Store in local file
api_headers = {'appId': "PBYIA5-2U0gvCvMTKXqC2Jb8Nzs9KhBZNkw6WcLLkYo",
               'key': "iXMKG8VvpdkpSKn1ezkJWYpNbb5tPVRS2z5nUFYtdGTP5sREmONVF_fColzk40JeKSZeG5T-s7c_ElYgXsHnag"}


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
            items = requests.get(API_HOST+"items/"+uid, headers=api_headers)
            if (items.json()):
                jitems = items.json()

            for i in jitems:
                res = requests.get(API_HOST+"inventory/%s" %
                                   i['itemhash'], headers=api_headers)
                item = res.json()
                print(item)
                public = item['public']
                i['public'] = public

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
            # catch inactive users
            if (not isUserActive(user.email)):
                return render_template("confirm.jinja", email=user.email)

            login_user(user)

            next = request.args.get('next')
            if (not forms.is_safe_url(next)):
                return abort(400)
            return redirect(next or '/')
        return render_template('login.jinja', title="Log In")
    else:
        email = request.args.get("email")
        if (not email):
            email = ""
        return render_template('login.jinja', title="Log In", email=email)


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
            return signup(user.email, user.password)
        else:
            return redirect('/register')
    else:
        return render_template("register.jinja", title="New Account", current_user=current_user)


def getEmailFromCode(code):
    return codesdb[code]['email']


@app.route("/confirm", methods=["GET"])
def confirmEmail():
    code = request.args.get("code")
    if (not code):
        abort(Response("Confirmation code in URL required."))

    # get email from code
    email = getEmailFromCode(code)

    if ('confirmation_key' in usersdb[email]):
        return redirect("/login?email=%s" % email)

    # generate random password for ETH account
    # epass = randomPass()
    epass = "TODO: FIX RANDOM PASS GENERATOR"

    # create new ETH account
    rdata = {"password": epass}
    account = requests.post(
        API_HOST+"ethUser", json=rdata, headers=api_headers)
    account = account.json()

    # add account index to DB datapage
    userDoc = usersdb[email]
    userDoc['eth_index'] = account['index']
    userDoc['eth_password'] = epass
    userDoc['confirmation_code'] = code

    udb_res = userDoc.save()
    print(udb_res)

    return redirect("/login?email=%s" % email)


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
    fileup = request.files['upfile']
    item = request.form['inventoryItem']
    userIndex = request.form['userIndex']
    if 'public' in request.form:
        public = 'True'
    else:
        public = 'False'

    # generate secure filename for upfile
    sfn = secure_filename(fileup.filename)
    # save file locally
    fileup.save(sfn)

    # pack up request data to forward to API_HOST
    jdata = {'inventoryItem': item, 'userIndex': userIndex, 'public': public}
    f_u = {'upfile': open(sfn, 'rb')}

    # send request to API_HOST
    res = requests.post(API_HOST + "inventory",
                        files=f_u, data=jdata, headers=api_headers)

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
    res = requests.get(API_HOST+"inventory/%s" % itemhash, headers=api_headers)
    return res.json()


def itempageTemplate(itemhash, fileItem, name, owner=None, public=False):
    scansReq = requests.get(API_HOST+"scans/"+itemhash, headers=api_headers)
    scans = scansReq.json()

    txReq = requests.get(API_HOST + "transfers/" +
                         itemhash, headers=api_headers)
    transfers = txReq.json()

    return render_template("item.jinja",
                           filename=fileItem['Name'],
                           filehash=fileItem['Hash'],
                           itemhash=itemhash,
                           title=name,
                           scans=scans,
                           transfers=transfers,
                           current_user=current_user,
                           owner=owner,
                           public=public)


@app.route("/item/<itemhash>", methods=["GET"])
def itempage(itemhash):
    res = getItem(itemhash)
    fileItem = res['fileHash']
    name = res['inventoryItem']['name']
    public = res['public']
    owner = res['inventoryItem']['owner']

    if (not public):
        if hasattr(current_user, "email") and current_user.email == owner:
            return itempageTemplate(itemhash, fileItem, name, owner, public=public)
        else:
            return render_template("sowwy.jinja", title="Rekt", message="You do not have access to this item. Please log in to view it.", login_required=True)
    else:
        return itempageTemplate(itemhash, fileItem, name, owner, public=public)


# file proxy
# DON'T USE @login_required -- items can be public
@app.route("/file/<hash>")
def file(hash):
    # get filename from API
    url = API_HOST + "inventory/%s" % hash
    res = requests.get(url, headers=api_headers)
    jdata = res.json()
    filename = jdata['fileHash']['Name']
    public = jdata['public']
    owner = jdata['inventoryItem']['owner']
    print(filename)

    # prevent downloads from unauthorized parties
    if (not public):
        if (not hasattr(current_user, "email") or current_user.email != owner):
            return "UNAUTHORIZED"

    # get raw file from API
    url = API_HOST + "file/%s" % hash
    res = requests.get(url, stream=True, headers=api_headers)

    # read out file to local tempfile
    with open('temp', 'wb') as out_file:
        shutil.copyfileobj(res.raw, out_file)
    del res

    # send it
    return send_file('temp', as_attachment=True, attachment_filename=filename)


# smart tag scan
# DON'T USE @login_required -- we still need to render a page for anons
@app.route("/scan/<hash>")
def scanTag(hash):
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip = (request.environ['REMOTE_ADDR'])
        print("BOOOO")
    else:
        ip = (request.environ['HTTP_X_FORWARDED_FOR'])  # if behind a proxy

    jdata = {'itemId': str(hash)}
    sdata = {'date': str(datetime.datetime.now()),
             'ip': ip}

    if (hasattr(current_user, "email")):
        sdata['user'] = current_user.email
    else:
        sdata['user'] = "anonymous @ " + ip

    jdata['scanData'] = json.dumps(sdata)

    # send scan request to API
    tx = requests.post(API_HOST+"scan", json=jdata, headers=api_headers)
    txid = tx.json()

    # send notice to owner
    recipient = "test@10.0.0.129"
    msg = Message("Item scanned", recipients=[recipient])
    msg.body = "Item %s has been scanned by %s (%s)" % (
        hash, sdata['user'], ip)
    mail.send(msg)

    return render_template("scan.jinja", title="scan", txid=txid, itemhash=str(hash))


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

    try:
        user = usersdb[current_user.email]
        newOwner = usersdb[newOwnerEmail]

        jdata = {
            "userIndex": int(user['eth_index']),
            "userPass": user['eth_password'],
            "itemhash": itemhash,
            "newOwnerIndex": int(newOwner['eth_index']),
            "newOwner": newOwnerEmail
        }

        res = requests.post(API_HOST+"transfer",
                            json=jdata, headers=api_headers)

        txhash = (res.text).replace('"', '')

        return render_template("tx-success.jinja", newOwner=newOwnerEmail, txHash=txhash)
    except KeyError:
        return render_template("sowwy.jinja", title="New Friend Alert", message="We couldn't find an account with that email address.", invite=newOwnerEmail)


@app.route("/invite", methods=["GET"])
@login_required
def send_invite():
    nEmail = request.args.get('email', default="none")
    if (nEmail != "none"):
        msg = Message("LedgerCTRL Invite", recipients=[nEmail])
        msg.html = "%s has invited you to view an item on the blockchain. Sign up on <a href='http://ctrl.vaasd.com/register'>LedgerCTRL</a> to access it!" % current_user.email
        mail.send(msg)
        return render_template("notice.jinja", title="Invite sent", heading="Invitation sent!", message="We just invited %s to LedgerCTRL -- hope they bring beer." % nEmail, info="Wine is also good.")
    else:
        return render_template("sowwy.jinja", title="Dun goofed ¯\\_(ツ)_/¯", message="You need to provide an email to invite in the URL parameters.")


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

    if (data['_id'] in usersdb):
        return "USER ALREADY EXISTS"

    # generate confirmation code
    code = secrets.token_urlsafe()
    secretdata = {'_id': code, 'email': email}

    # save confirmation/email pair to codes DB
    sdoc = codesdb.create_document(secretdata)
    print(sdoc)

    # (preemptively) add user to users DB
    doc = usersdb.create_document(data)
    print(doc)

    msg = Message("LedgerCTRL Account Confirmation", recipients=[email])
    # TODO: change to https
    url = 'http://%sconfirm?code=%s' % (LOCAL_HOST, code)
    msg.html = """<h2>Confirm your email address</h2>
        <p>Click the following link to confirm your email:</p>
        <a href="%s">%s</a>""" % (url, url)
    mail.send(msg)

    return render_template("confirm.jinja", title="Needs More Confirm", email=email)


def isUserActive(email):
    user = usersdb[email]
    if ('confirmation_code' in user):
        return user['confirmation_code']
    else:
        return None


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
