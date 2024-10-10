#!/bin/bash

# client  common  docker-compose.yaml  gateway  inventory  README.md  restock  run.sh
which cargo

sudo docker-compose up -d && \
    cargo watch -C client -q -x r & \
    cargo watch -C restock -q -x r & \
    cargo watch -C inventory -q -x r & \
    cargo watch -C gateway -q -x r & \
    echo 'running'
