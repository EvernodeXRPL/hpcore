FROM hpcore:latest as hpcore-nodejs

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y curl
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash -
RUN apt-get install -y nodejs

FROM hpcore-nodejs

RUN /hp/hpcore new /echocontract
COPY ./examples/echocontract/contract.js /echocontract/bin/contract.js
RUN mv /echocontract/cfg/hp.cfg /echocontract/cfg/hp.json
RUN node -p "JSON.stringify({...require('/echocontract/cfg/hp.json'), binary:'/usr/bin/node', binargs:'./bin/contract.js' }, null, 2)" > /echocontract/cfg/hp.cfg
RUN rm /echocontract/cfg/hp.json

ENTRYPOINT ["/hp/hpcore", "run", "/echocontract"]