#!/bin/bash

repo=hotpocketdev/hotpocket

./build.sh
docker push $repo:buster
docker push $repo:njs.14