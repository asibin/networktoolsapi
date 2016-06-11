FROM ubuntu:latest
MAINTAINER  Sibin Arsenijevic "sibin.arsenijevic@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential git wget
RUN git clone https://github.com/asibin/networktoolsapi.git
RUN wget -q 'http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz'
RUN wget -q 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz'
RUN gunzip -c GeoIPASNum.dat.gz > /networktoolsapi/networktoolsapi/static/data/GeoIPASNum.dat
RUN gunzip -c GeoLiteCity.dat.gz > /networktoolsapi/networktoolsapi/static/data/GeoLiteCity.dat
WORKDIR /networktoolsapi
RUN pip install -r requirements.txt
CMD ["python runserver.py"]
