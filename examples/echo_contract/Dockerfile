FROM hpcore:latest as hpcore-nodejs

RUN apt-get update
RUN apt-get install -y build-essential
RUN apt-get install -y curl
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash -
RUN apt-get install -y nodejs

FROM hpcore-nodejs

RUN /hp/hpcore new /echo_contract
COPY ./examples/echo_contract/contract.js /echo_contract/bin/contract.js
RUN mv /echo_contract/cfg/hp.cfg /echo_contract/cfg/hp.json
RUN node -p "JSON.stringify({...require('/echo_contract/cfg/hp.json'), binary:'/usr/bin/node', binargs:'./bin/contract.js' }, null, 2)" > /echo_contract/cfg/hp.cfg
RUN rm /echo_contract/cfg/hp.json

ENTRYPOINT ["/hp/hpcore", "run", "/echo_contract"]