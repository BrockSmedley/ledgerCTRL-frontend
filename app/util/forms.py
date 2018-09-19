from wtforms import Form, BooleanField, StringField, validators


class UserForm(Form):
    email = StringField('email', [validators.Length(min=6, max=30)])
    password = StringField('password', [validators.Length(min=8, max=40)])


class RegistrationForm(UserForm):
    agreeTerms = BooleanField('I accept the terms & conditions', [
        validators.InputRequired()])


def register(request):
    form = RegistrationForm(request.form)
    print("FORM:")
    print(form)
    if (request.method == "POST" and form.validate()):
        email = form.email.data
        password = form.password.data
        user = User(email, password)
        return user
    else:
        return None


class User():
    email = ""
    password = ""

    def __init__(self, email="", password=""):
        self.email = email
        self.password = password
