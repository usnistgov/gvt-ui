#!/bin/bash

if [ "$#" -eq 0 ]; then
  echo "No arguments were provided."
  exit
fi

if [ -n "$1" ]; then
 echo "buildind, tagging and pushing $1"
 cd hit-base-web/client
 grunt build
 cd ../..
 mvn install -f ~/workspace/unified-report/unified-report/ && mvn install -f ~/workspace/hit-core && mvn install -f ~/workspace/hit-core-hl7v2/ && mvn install -f ~/workspace/gvt/gvt-resource-bundle/ && mvn install -f ~/workspace/gvt/gvt-core/  && mvn install -f ~/workspace/gvt/gvt-plugins/ && mvn install -f ~/workspace/gvt/gvt-config/ && mvn install -f ~/workspace/gvt/gvt-ui/

 docker compose build
 docker image tag nist775hit/gvt-tool nist775hit/gvt-tool:$1
 docker image tag nist775hit/gvt-tool nist775hit/gvt-tool:latest
 docker image tag nist775hit/gvt-mysql nist775hit/gvt-mysql:$1
 docker image tag nist775hit/gvt-mysql nist775hit/gvt-mysql:latest
 
 
 docker push nist775hit/gvt-tool:$1
 docker push nist775hit/gvt-mysql:$1
 docker push nist775hit/gvt-tool:latest
 docker push nist775hit/gvt-mysql:latest
fi
