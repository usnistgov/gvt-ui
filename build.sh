#!/bin/bash
echo "building..."
cd hit-base-web/client
grunt build
cd ../..
mvn install -f ~/workspace/unified-report/unified-report/ && mvn install -f ~/workspace/hit-core && mvn install -f ~/workspace/hit-core-hl7v2/ && mvn install -f ~/workspace/gvt/gvt-resource-bundle/ && mvn install -f ~/workspace/gvt/gvt-core/  && mvn install -f ~/workspace/gvt/gvt-plugins/ && mvn install -f ~/workspace/gvt/gvt-config/ && mvn install -f ~/workspace/gvt/gvt-ui/
fi
