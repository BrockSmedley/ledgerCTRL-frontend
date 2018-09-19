from wtforms import Form, BooleanField, StringField, validators
from . import user as User
from urllib.parse import urlparse, urljoin
from flask import request, url_for, redirect


class UserForm(Form):
    email = StringField('email', [validators.Length(min=6, max=30)])
    password = StringField('password', [validators.Length(min=8, max=40)])


class RegistrationForm(UserForm):
    agreeTerms = BooleanField('I accept the terms & conditions', [
        validators.InputRequired()])


def validateUser(request):
    form = UserForm(request.form)
    if (request.method == "POST" and form.validate()):
        email = form.email.data
        password = form.password.data
        user = User.User(email, password)
        return user
    else:
        return None


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


def get_redirect_target():
    for target in request.values.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target


def redirect_back(endpoint, **values):
    target = request.form['next']
    if not target or not is_safe_url(target):
        target = url_for(endpoint, **values)
    return redirect(target)
