from flask import Flask, render_template
app = Flask(__name__, static_url_path="", static_folder="static")


@app.route("/")
def main():
    return render_template("index.html")


@app.route("/upload")
def upload():
    return render_template("upload.html")


if __name__ == "__main__":
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, port=80)
