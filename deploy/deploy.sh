#!/usr/bin/env bash
set -e
set -o pipefail


export SECRETS=${APP_NAME}-secrets
export SECRETS_FN=$HOME/${SECRETS}
export IMAGE_NAME=gcr.io/${GCLOUD_PROJECT}/${APP_NAME}
export RESERVED_IP_NAME=${NS_NAME}-${APP_NAME}-ip
docker rmi -f $IMAGE_NAME
cd $ROOT_DIR
gcloud compute addresses list --format json | jq '.[].name' -r | grep $RESERVED_IP_NAME || gcloud compute addresses create $RESERVED_IP_NAME --global
./gradlew  bootBuildImage --imageName=$IMAGE_NAME
docker push $IMAGE_NAME
touch $SECRETS_FN
echo writing to "$SECRETS_FN "
cat <<EOF >${SECRETS_FN}
DB_HOST=${DB_HOST}
DB_USERNAME=${DB_USERNAME}
DB_PASSWORD=${DB_PASSWORD}
DB_SCHEMA=${DB_SCHEMA}
TWIS_CLIENT_KEY=${TWIS_CLIENT_KEY}
TWIS_CLIENT_KEY_SECRET=${TWIS_CLIENT_KEY_SECRET}
TWIS_USER=${TWIS_USER}
TWIS_PASSWORD=${TWIS_PASSWORD}
SOCIALHUB_JOSHLONG_CLIENT_KEY=${SOCIALHUB_JOSHLONG_CLIENT_KEY}
SOCIALHUB_JOSHLONG_CLIENT_KEY_SECRET=${SOCIALHUB_JOSHLONG_CLIENT_KEY_SECRET}
JWK_KEY_PRIVATE=${AUTHORIZATION_SERVER_JWK_KEY_PRIVATE}
JWK_KEY_PUBLIC=${AUTHORIZATION_SERVER_JWK_KEY_PUBLIC}
EOF
kubectl delete secrets $SECRETS || echo "no secrets to delete."
kubectl create secret generic $SECRETS --from-env-file $SECRETS_FN
kubectl delete -f $ROOT_DIR/deploy/k8s/deployment.yaml || echo "couldn't delete the deployment as there was nothing deployed."
kubectl apply -f $ROOT_DIR/deploy/k8s

