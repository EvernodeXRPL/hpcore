#!/bin/bash

hpcoredir=$(realpath ../..)
docker build -t hpcore:focal -f ./Dockerfile.hp-ubuntu-focal $hpcoredir