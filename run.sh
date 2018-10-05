docker stop ledgerfy
docker rm ledgerfy

docker run -dit -p 8099:80 -p 80:80 --name ledgerfy --network vaas2_vaasnet ledgerfy
