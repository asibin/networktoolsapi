FROM ubuntu:latest
MAINTAINER  Sibin Arsenijevic "sibin.arsenijevic@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python runserver.py"]
