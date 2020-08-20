# We are going with NodeJs debian docker image because sample contracts need NodeJs to run.
# Otherwise, hpcore itself can run on any docker image like ubuntu or debian without NodeJs.
FROM node:12.18.3-buster-slim

RUN apt-get update
# Install netcat for websocketd <--> domain socket redirection.
RUN apt-get install -y netcat-openbsd libgomp1

# Install shared libraries.
# Copy shared libraries and register it.
COPY ./bin/libfuse3.so.3 /usr/local/lib/
COPY ./bin/libblake3.so /usr/local/lib/
RUN ldconfig
COPY ./bin/fusermount3 /usr/local/bin/

# hpcore binary is copied to /hp directory withtin the docker image.
WORKDIR /hp
COPY ./bin/hpcore .
COPY ./bin/hpfs .
COPY ./bin/websocketd .
COPY ./bin/websocat .

ENTRYPOINT ["/hp/hpcore"]