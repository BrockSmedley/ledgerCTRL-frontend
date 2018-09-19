from flask_login import UserMixin


class User(UserMixin):
    email = ""
    password = ""

    def __init__(self, email="", password=""):
        self.email = email
        self.password = password

    def get_id(self):
        return self.email
