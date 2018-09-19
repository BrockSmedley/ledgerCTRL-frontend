FROM tiangolo/uwsgi-nginx-flask:python3.6

RUN pip install requests Cloudant WTForms

COPY ./app /app
