#!/bin/bash
cd hit-base-web/client
grunt build
cd ../..

if [ "$1" = "clean" ]; then
	mvn clean install -f ~/workspace/unified-report/unified-report/ && mvn clean install -f ~/workspace/hit-core && mvn clean install -f ~/workspace/hit-core-hl7v2/ && mvn clean install -f ~/workspace/gvt/gvt-resource-bundle/ && mvn clean install -f ~/workspace/gvt/gvt-core/ && mvn clean install -f ~/workspace/gvt/gvt-plugins/ && mvn clean install -f ~/workspace/gvt/gvt-config/ && mvn clean install -f ~/workspace/gvt/gvt-ui/
else
	mvn install -f ~/workspace/unified-report/unified-report/ && mvn install -f ~/workspace/hit-core && mvn install -f ~/workspace/hit-core-hl7v2/ && mvn install -f ~/workspace/gvt/gvt-resource-bundle/ && mvn install -f ~/workspace/gvt/gvt-core/  && mvn install -f ~/workspace/gvt/gvt-plugins/ && mvn install -f ~/workspace/gvt/gvt-config/ && mvn install -f ~/workspace/gvt/gvt-ui/
fi

docker compose build
docker image tag nist775hit/gvt-tool nist775hit/gvt-tool:dev
docker image tag nist775hit/gvt-mysql nist775hit/gvt-mysql:dev

docker push nist775hit/gvt-tool:dev
docker push nist775hit/gvt-mysql:dev
