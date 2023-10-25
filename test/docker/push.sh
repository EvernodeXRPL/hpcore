#!/bin/bash
# Pushes all the HotPocket images into docker hub.

img=evernodedev/hotpocket

docker image push $img:udpvisa-test-0.0.1-ubt.20.04
docker image push $img:udpvisa-test-0.0.1-ubt.20.04-njs.20