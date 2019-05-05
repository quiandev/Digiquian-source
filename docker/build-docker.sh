#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-digiquianpay/digiquiand-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/digiquiand docker/bin/
cp $BUILD_DIR/src/digiquian-cli docker/bin/
cp $BUILD_DIR/src/digiquian-tx docker/bin/
strip docker/bin/digiquiand
strip docker/bin/digiquian-cli
strip docker/bin/digiquian-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
