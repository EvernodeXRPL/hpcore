#!/bin/bash

repo=hotpocketdev/hotpocket

./build.sh
docker push $repo:ubt.20.04
docker push $repo:njs.14