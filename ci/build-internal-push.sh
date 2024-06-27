#! /bin/sh
set -x

# Gitlab creates different variables depending on if this is a MR pipeline or not
# Only one of these should have a value, so the resulting tag name takes the correct value
export BRANCH=${CI_COMMIT_BRANCH}${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME}${CI_COMMIT_TAG}
export IDA_IMAGE="registry.acce.ciphertechsolutions.com/acce_internal/ida:8.2.2"

# Login to the Harbor registry to push the images
docker login --username ${HARBOR_CI_USERNAME} --password ${HARBOR_CI_PASSWORD} ${HARBOR_HOST}
docker pull ${IDA_IMAGE}

# Replace ssh with https for runner
sed -i "s/git+ssh:\/\/git/git+https:\/\/gitlab-ci-token:\${CI_JOB_TOKEN}/" ./os_acce_parsers/services/parsers/build.toml

# Required as Docker does not support conditional copies, even if directory is empty
mkdir wheels
# Build and push the dev version
python3 ./os_acce_parsers/services/build.py -d --build-arg index_url=$ACCE_INDEX_URL -r ${HARBOR_HOST}/acce_internal -t dev ${SERVICE_TAG} --build-arg ida_image=${IDA_IMAGE} --load
if [ $? -eq 0 ] 
then 
  echo "Docker build successful" 
else 
  echo "Docker build failed"
  exit 1 
fi
docker push ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:dev

# Tag and push the "branch-name" version
docker tag ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:dev ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:${BRANCH}
docker push ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:${BRANCH}

# Check if this is the result of a tag and if so, tag and push to production
if [ "${CI_COMMIT_TAG}" ]; then
  echo "Tagging latest version ${CI_COMMIT_TAG}"
  docker tag ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:dev ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:latest
  docker tag ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:latest ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:${CI_COMMIT_TAG}
  docker push ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:latest
  docker push ${HARBOR_HOST}/acce_internal/${IMAGE_NAME}:${CI_COMMIT_TAG}
fi
