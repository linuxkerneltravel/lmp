unset DOCKER_TLS_VERIFY
unset DOCKER_HOST
unset DOCKER_CERT_PATH
unset MINIKUBE_ACTIVE_DOCKERD
export MINIKUBE_ROOT_PID=$(docker inspect $(docker ps | grep minikube | awk -F ' ' '{print $1}') -f '{{.State.Pid}}')

export MINIKUBE_STARTED=TRUE
eval $(minikube -p minikube docker-env)
