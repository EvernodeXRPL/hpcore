FROM ubuntu:bionic

WORKDIR /hp
COPY ./build/hpcore .
ENTRYPOINT ["/hp/hpcore"]