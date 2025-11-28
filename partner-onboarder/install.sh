#!/bin/bash
# Onboards default partners
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

  function installing_onboarder() {

  read -p "Is values.yaml for onboarder chart set correctly as part of pre-requisites? (Y/n) : " yn;
  if [[ $yn = "Y" ]] || [[ $yn = "y" ]] ; then
    NFS_OPTION=''
    S3_OPTION=''
    config_complete=false  # flag to check if S3 or NFS is configured
    while [ "$config_complete" = false ]; do
      read -p "Do you have S3 details for storing Onboarder reports? (Y/n) : " ans
      if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
        read -p "Please provide S3 host: " s3_host
        if [[ -z $s3_host ]]; then
          echo "S3 host not provided; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 region: " s3_region
        if [[ $s3_region == *[' !@#$%^&*()+']* ]]; then
          echo "S3 region should not contain spaces or special characters; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 bucket: " s3_bucket
        if [[ $s3_bucket == *[' !@#$%^&*()+']* ]]; then
          echo "S3 bucket should not contain spaces or special characters; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 access key: " s3_user_key
        if [[ -z $s3_user_key ]]; then
          echo "S3 access key not provided; EXITING;"
          exit 1;
        fi
        read -p "Please provide S3 secret key: " s3_secret_key
        if [[ -z $s3_secret_key ]]; then
          echo "S3 secret key not provided; EXITING;"
          exit 1;
        fi
        S3_OPTION="--set onboarding.configmaps.s3.s3-host=$s3_host --set onboarding.configmaps.s3.s3-user-key=$s3_user_key --set onboarding.configmaps.s3.s3-region=$s3_region --set onboarding.configmaps.s3.s3-bucket-name=$s3_bucket --set onboarding.secrets.s3.s3-user-secret=$s3_secret_key"
        push_reports_to_s3=true
        config_complete=true
      elif [[ "$ans" == "n" || "$ans" == "N" ]]; then
        push_reports_to_s3=false
        read -p "Since S3 details are not available, do you want to use NFS directory mount for storing reports? (y/n) : " answer
        if [[ $answer == "Y" ]] || [[ $answer == "y" ]]; then
          read -p "Please provide NFS Server IP: " nfs_server
          if [[ -z $nfs_server ]]; then
            echo "NFS server not provided; EXITING."
            exit 1;
          fi
          read -p "Please provide NFS directory to store reports from NFS server (e.g. /srv/nfs/<sandbox>/onboarder/), make sure permission is 777 for the folder: " nfs_path
          if [[ -z $nfs_path ]]; then
            echo "NFS Path not provided; EXITING."
            exit 1;
          fi
          NFS_OPTION="--set onboarding.volumes.reports.nfs.server=$nfs_server --set onboarding.volumes.reports.nfs.path=$nfs_path"
          config_complete=true
        else
          echo "Please rerun the script with either S3 or NFS server details."
          exit 1;
        fi
      else
        echo "Invalid input. Please respond with Y (yes) or N (no)."
      fi
    done
  echo "Choose the namespace to run the onboarder in:"
      read -p "Enter the custom namespace: " custom_ns
            if [[ -z "$custom_ns" ]]; then
              echo "No namespace provided; EXITING."
              exit 1;
            fi
  echo "Do you have public domain & valid SSL? (Y/n) "
  echo "Y: if you have public domain & valid ssl certificate"
  echo "n: if you don't have a public domain and a valid SSL certificate. It will add an ssl certificate in onboarder docker. Only recommended in testing env."
  read -p "" flag

  if [ -z "$flag" ]; then
    echo "'flag' was not provided; EXITING;"
    exit 1;
  fi
  ENABLE_INSECURE=''
  if [ "$flag" = "n" ]; then
    ENABLE_INSECURE='--set onboarding.configmaps.onboarding.ENABLE_INSECURE=true';
  fi

  export NS=$custom_ns
  CHART_VERSION=1.3.0-beta.1

  echo Create $NS namespace
  kubectl create ns $NS || true

  echo Istio label
  kubectl label ns $NS istio-injection=disabled --overwrite
  helm repo update

  echo Copy configmaps
  kubectl -n $NS --ignore-not-found=true delete cm s3
  sed -i 's/\r$//' copy_cm.sh
  ./copy_cm.sh
  echo Copy secrets
  sed -i 's/\r$//' copy_secrets.sh
  ./copy_secrets.sh

  echo Onboarding Mimoto OIDC partner
  helm -n $NS install mimoto-partner-onboarder mosip/partner-onboarder \
    $NFS_OPTION \
    $S3_OPTION \
    --set onboarding.variables.push_reports_to_s3=$push_reports_to_s3 \
    --set extraEnvVars[0].name=customnamespace,extraEnvVars[0].value=$NS \
    --set extraEnvVarsCM[0]=global \
    --set extraEnvVarsCM[1]=keycloak-env-vars \
    --set extraEnvVarsCM[2]=keycloak-host \
    $ENABLE_INSECURE \
    -f values.yaml \
    --version $CHART_VERSION \
    --wait --wait-for-jobs

    echo Updating mimoto-oidc-keystore-password value
    kubectl -n $NS create secret generic mimoto-oidc-keystore-password --from-literal=mimoto-oidc-keystore-password='mosip123' --dry-run=client -o yaml | kubectl apply -f -
    ./copy_cm_func.sh secret mimoto-oidc-keystore-password $NS config-server

    echo Updating Mimoto wallet binding partner api key and Mimoto OIDC Partner Client ID
    ./copy_cm_func.sh secret mimoto-wallet-binding-partner-api-key $NS config-server
    ./copy_cm_func.sh secret mimoto-oidc-partner-clientid $NS config-server
    kubectl -n config-server set env --keys=mimoto-wallet-binding-partner-api-key --from secret/mimoto-wallet-binding-partner-api-key deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
    kubectl -n config-server set env --keys=mimoto-oidc-partner-clientid --from secret/mimoto-oidc-partner-clientid deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
    kubectl -n config-server set env --keys=mimoto-oidc-keystore-password --from secret/mimoto-oidc-keystore-password deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

    kubectl -n config-server rollout restart deployment config-server
    kubectl -n config-server rollout status deployment config-server

    echo Reports are moved to S3 under onboarder bucket
    return 0
  fi
}

# set commands for error handling.
set -e
set -o errexit   ## set -e : exit the script if any statement returns a non-true return value
set -o nounset   ## set -u : exit the script if you try to use an uninitialised variable
set -o errtrace  # trace ERR through 'time command' and other functions
set -o pipefail  # trace ERR through pipes
installing_onboarder   # calling function