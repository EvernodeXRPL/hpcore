#!/bin/bash
# Pushes all the HotPocket images into docker hub.

img=evernode/hotpocket

docker image push "$img:test-ubt.20.04"
docker image push "$img:test-ubt.20.04-njs.20"