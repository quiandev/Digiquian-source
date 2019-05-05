FROM debian:stretch
LABEL maintainer="digiquian Developers <dev@digiquian.org>"
LABEL description="Dockerised digiquianCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
