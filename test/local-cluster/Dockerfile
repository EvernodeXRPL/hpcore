# We are going with NodeJs debian docker image because sample contracts need NodeJs to run.
# Otherwise, hpcore itself can run on any docker image like ubuntu or debian without NodeJs.
FROM node:10.17.0-buster-slim

RUN apt-get update
# Install netcat for websocketd <--> domain socket redirection.
RUN apt-get install -y netcat-openbsd

# Install fuse.
# Copy fuse shared library and register it.
COPY ./bin/libfuse3.so.3 /usr/local/lib/
RUN ldconfig
COPY ./bin/fusermount3 /usr/local/bin/

# hpcore binary is copied to /hp directory withtin the docker image.
WORKDIR /hp
COPY ./bin/hpcore .
COPY ./bin/hpstatemon .
COPY ./bin/websocketd .
COPY ./bin/websocat .

ENTRYPOINT ["/hp/hpcore"]