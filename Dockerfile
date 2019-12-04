# We are going with NodeJs debian docker image because sample contracts need NodeJs to run.
# Otherwise, hpcore itself can run on any docker image like ubuntu or debian without NodeJs.
FROM node:10.17.0-buster-slim

# Install fuse.
# Copy fuse shared library and register it.
COPY ./libfuse3.so.3 /usr/local/lib/
RUN ldconfig
COPY ./fusermount3 /usr/local/bin/

# hpcore binary is copied to /hp directory withtin the docker image.
WORKDIR /hp
COPY ./build/hpcore .
COPY ./build/hpstatemon .
ENTRYPOINT ["/hp/hpcore"]