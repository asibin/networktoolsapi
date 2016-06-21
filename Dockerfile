# DISCLAIMER:
# THIS DOCKER CONTAINER IS JUST FOR DEMONSTRATION PURPOSES,
# IT IS NOT SUPPOSED TO RUN IN A PRODUCTION ENVIRONMENT
# FOR PRODUCTION USE uWSGI AND A PROPER WEBSERVER

FROM ubuntu:latest

MAINTAINER  Sibin Arsenijevic "sibin.arsenijevic@gmail.com"

# Install essentials
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential git wget

# Clone the latest version of project
RUN git clone 'https://github.com/asibin/networktoolsapi.git'

# Setup free MaxMind databases
RUN wget -q 'http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz'
RUN wget -q 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz'
RUN gunzip -c GeoIPASNum.dat.gz > /networktoolsapi/networktools/static/data/GeoIPASNum.dat
RUN gunzip -c GeoLiteCity.dat.gz > /networktoolsapi/networktools/static/data/GeoLiteCity.dat

WORKDIR /networktoolsapi

# Install the requirements
RUN pip install -r requirements.txt

# Start project
#CMD ["python", "runserver.py"]
CMD ["python", "tests/tests.py"]
