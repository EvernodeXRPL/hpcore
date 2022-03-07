#!/bin/bash
# Pushes all the Hot Pocket images into docker hub.

img=evernodedev/hotpocket

docker image push --all-tags $img