#!/bin/bash

# To connect to docker cluster node.
docker run -i -t --rm --network=hpnet hp:text_client

# To connect to localhost node.
# docker run -i -t --rm --network=host hp:text_client
