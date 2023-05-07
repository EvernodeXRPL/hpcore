#!/bin/bash
# Pushes all the HotPocket images into docker hub.

img=evernodedev/hotpocket

docker image push --all-tags $img