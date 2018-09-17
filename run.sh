docker stop ledgerfy
docker rm ledgerfy

docker run -it -p 80:80 --name ledgerfy ledgerfy