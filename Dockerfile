FROM tiangolo/uwsgi-nginx-flask:python3.6

ADD ./requirements.txt /app
WORKDIR /app
RUN pip install -r requirements.txt

ENV LISTEN_PORT 80
EXPOSE 80

COPY ./ipf.conf /etc/nginx/conf.d/ipf.conf

COPY ./app /app
