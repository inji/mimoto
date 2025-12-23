# Deployment

## Pre-requisites
* Base infrastructure setup
   * Tools and utilities to be installed locally [steps](https://docs.inji.io/readme/setup/deploy#tools-and-utilities)
   * System Requirements: Hardware, network and certificate requirements [steps](https://docs.inji.io/readme/setup/deploy#system-requirements)
   * Set up Wireguard Bastion Host [steps](https://docs.inji.io/readme/setup/deploy#wireguard)
   * K8s Cluster setup [steps](https://docs.inji.io/readme/setup/deploy#k8-cluster-setup)
   * NGINX setup and configuration [steps](https://docs.inji.io/readme/setup/deploy#nginx-for-inji-k8-cluster)
   * K8s Cluster Configuration [steps](https://docs.inji.io/readme/setup/deploy#k8-cluster-configuration)
* inji-stack-config ConfigMap [steps](https://docs.inji.io/readme/setup/deploy#pre-requisites)
* Postgres installation [steps](https://github.com/mosip/mosip-infra/tree/v1.2.0.2/deployment/v3/external/postgres)
   * Note: Before running the Postgres install script, update the `POSTGRES_HOST` value in `install.sh` with the correct PostgreSQL host.
* Config server secerts [steps](https://github.com/mosip/mosip-infra/tree/v1.2.0.2/deployment/v3/mosip/conf-secrets)
* Config server installation [steps](https://docs.inji.io/readme/setup/deploy#config-server-installation)
* Artifactory installation [steps](https://github.com/mosip/artifactory-ref-impl/tree/v1.3.0-beta.2/deploy)

* Redis installation
```
cd deploy/redis
./install.sh
```
## Initialise pre-requisites
### [DB init](../db_scripts)
* Update values file for postgres init [here](../db_scripts/init_values.yaml).
````
   cd ../../db_scripts
  ./init_db.sh
```` 

## [Install Onboarder](../partner-onboarder)
* Execute Onboarder install script
```
cd ../partner-onboarder
./install.sh
 ```
* During the execution of the `install.sh` script, a prompt appears requesting information for the S3 bucket, including its name and URL.
* Once the job is completed, log in to S3 / NFS and check the reports. There should not be any failures.
* Note: If you are running the Onboarder in a separate INJI cluster, update the extraEnvVars section accordingly in [values.yaml](../partner-onboarder/values.yaml).

## Install mimoto and datashare
* Execute mimoto install script
* Before installing Mimoto, please ensure that the database host and port are correctly configured in the [values.yaml](mimoto/values.yaml) file.
* **Datashare Deployment:**
  * If you are using **Inji Web Wallet**, datashare will be deployed as part of the Mimoto installation.
  * If you are using only **Inji Mobile Wallet**, datashare deployment is not required.
* Note: During the installation of Mimoto and Datashare, ensure that the active_profile_env parameter in the ConfigMap of the config-server-share (in the injiweb namespace) is set to: default,inji-default,standalone

### To Deploy Mimoto WITHOUT Datashare
If you are using only Inji Mobile Wallet and do not need datashare, follow these steps:

1. **Edit the install.sh script:**
   - Open `deploy/mimoto/install.sh`
   - Locate the datashare deployment section (around line 61-66)
   - Comment out or remove the following lines:
     ```bash
     INJI_DATASHARE_HOST=$(kubectl get cm inji-stack-config -o jsonpath={.data.inji-datashare-host})
     echo "Installing datashare"
     helm -n $NS install datashare-inji mosip/datashare \
     -f datashare-values.yaml \
     --version $DATASHARE_CHART_VERSION
     ```

2. **Configure Mimoto for Mobile Wallet only:**
   - Ensure that `qr_code_type` is set to `"EmbeddedVC"` in your `mimoto-issuers-config.json` file
   - This embeds the entire Verifiable Credential in the QR code.

3. **Run the modified install script:**
```bash
cd ../deploy/mimoto
./install.sh
 ```

### To Deploy Mimoto WITH Datashare (Default)
If you are using Inji Web Wallet or need datashare for online verification:
```
cd ../deploy/mimoto
./install.sh
 ```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

### For Onboarding new Issuer for VCI:

- create a folder "certs" in the root and a file "oidckeystore.p12" inside certs and store the keys as different aliases for every issuers. for more details refer [here](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers)

## [mimoto apitestrig](mimoto-apitestrig)
