#!/usr/bin/env bash
set -e
set -o pipefail

export APP_NAME=joshlong-api
export SECRETS=${APP_NAME}-secrets
export SECRETS_FN=$HOME/${SECRETS}
export IMAGE_NAME=gcr.io/${GCLOUD_PROJECT}/${APP_NAME}
export RESERVED_IP_NAME=${NS_NAME}-${APP_NAME}-ip
docker rmi -f $IMAGE_NAME
cd $ROOT_DIR
./mvnw -DskipTests=true spring-javaformat:apply clean package spring-boot:build-image -Dspring-boot.build-image.imageName=$IMAGE_NAME
docker push $IMAGE_NAME
gcloud compute addresses list --format json | jq '.[].name' -r | grep $RESERVED_IP_NAME || gcloud compute addresses create $RESERVED_IP_NAME --global
touch $SECRETS_FN
echo writing to "$SECRETS_FN "
cat <<EOF >${SECRETS_FN}
SPRING_R2DBC_URL=${SPRING_R2DBC_URL}
SPRING_R2DBC_USERNAME=${SPRING_R2DBC_USERNAME}
SPRING_R2DBC_PASSWORD=${SPRING_R2DBC_PASSWORD}
SPRING_RABBITMQ_HOST=${SPRING_RABBITMQ_HOST}
SPRING_RABBITMQ_PORT=${SPRING_RABBITMQ_PORT}
SPRING_RABBITMQ_USERNAME=${SPRING_RABBITMQ_USERNAME}
SPRING_RABBITMQ_PASSWORD=${SPRING_RABBITMQ_PASSWORD}
SPRING_RABBITMQ_VIRTUAL_HOST=${SPRING_RABBITMQ_VIRTUAL_HOST}
BOOTIFUL_YOUTUBE_API_KEY=${BOOTIFUL_YOUTUBE_API_KEY}
BOOTIFUL_BATCH_RUN=true
BOOTIFUL_PROMOTION_PLAYLIST_IDS=${BOOTIFUL_PROMOTION_PLAYLIST_IDS}
BOOTIFUL_TWITTER_CLIENT_ID=${BOOTIFUL_TWITTER_CLIENT_ID}
BOOTIFUL_TWITTER_CLIENT_SECRET=${BOOTIFUL_TWITTER_CLIENT_SECRET}
BLOG_INDEX_REBUILD_KEY=${BLOG_INDEX_REBUILD_KEY}
BOOTIFUL_PODCAST_API_SERVER_URI=https://api.bootifulpodcast.fm
EOF
kubectl delete secrets $SECRETS || echo "no secrets to delete."
kubectl create secret generic $SECRETS --from-env-file $SECRETS_FN
kubectl delete -f $ROOT_DIR/deploy/k8s/deployment.yaml || echo "couldn't delete the deployment as there was nothing deployed."
kubectl apply -f $ROOT_DIR/deploy/k8s
