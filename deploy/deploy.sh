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
EOF
kubectl delete secrets $SECRETS || echo "no secrets to delete."
kubectl create secret generic $SECRETS --from-env-file $SECRETS_FN
kubectl delete -f $ROOT_DIR/deploy/k8s/deployment.yaml || echo "couldn't delete the deployment as there was nothing deployed."
kubectl apply -f $ROOT_DIR/deploy/k8s
