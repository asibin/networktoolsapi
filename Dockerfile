# DISCLAIMER:
# THIS DOCKER CONTAINER IS JUST FOR DEMONSTRATION PURPOSES,
# IT IS NOT SUPPOSED TO RUN IN A PRODUCTION ENVIRONMENT
# FOR PRODUCTION USE uWSGI AND A PROPER WEBSERVER
MAINTAINER Sibin Arsenijevic "sibin.arsenijevic@gmail.com"

ARG maxmind_license_key

FROM ubuntu:16.04

# Install essentials
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential wget nmap

COPY . /networktoolsapi

# Setup free MaxMind databases
RUN wget -O GeoIPASNum.dat.tar.gz -q "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${maxmind_license_key}&suffix=tar.gz"
RUN wget -O GeoLiteCity.dat.tar.gz -q "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${maxmind_license_key}&suffix=tar.gz"
RUN tar -zxvf GeoIPASNum.dat.tar.gz && \
    mv GeoLite2-ASN_* GeoLite2-ASN && \
    mv GeoLite2-ASN/GeoLite2-ASN.mmdb /networktoolsapi/networktools/static/data/ && \
    rm -rf GeoLite2-ASN
RUN tar -zxvf GeoLiteCity.dat.tar.gz && \
    mv GeoLite2-City_* GeoLite2-City && \
    mv GeoLite2-City/GeoLite2-City.mmdb /networktoolsapi/networktools/static/data/ && \
    rm -rf GeoLite2-City

ENV PYTHONPATH /networktoolsapi

WORKDIR /networktoolsapi

# Install the requirements
RUN pip install -r requirements.txt

# Start project
CMD ["python", "runserver.py"]
