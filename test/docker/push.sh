#!/bin/bash
# Pushes all the HotPocket images into docker hub.

img=evernode/hotpocket

docker image push --all-tags $img