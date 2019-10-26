# We are going with NodeJs debian docker image because sample contracts need NodeJs to run.
# Otherwise, hpcore itself can run on any docker image like ubuntu or debian without NodeJs.
FROM node:10.17.0-buster-slim

# hpcore binary is copied to /hp directory withtin the docker image.
WORKDIR /hp
COPY ./build/hpcore .
ENTRYPOINT ["/hp/hpcore"]