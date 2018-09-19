FROM tiangolo/uwsgi-nginx-flask:python3.6

ADD ./requirements.txt /app
WORKDIR /app
RUN pip install -r requirements.txt

COPY ./app /app
