mkdir output

openssl req -new -x509 -keyout output/idserver.key -out output/idserver.crt -days 7305 -subj "/CN=ID-Server (update endpoint)" -config piratenid.openssl.cfg 
openssl req -new -x509 -keyout output/updater.key  -out output/updater.crt  -days 7305 -subj "/CN=PiratenID-Updater"           -config piratenid.openssl.cfg 

openssl x509 -in output/idserver.crt -subject -fingerprint -noout
openssl x509 -in output/updater.crt  -subject -fingerprint -noout

cat output/updater.key output/updater.crt > output/updater-combined.key