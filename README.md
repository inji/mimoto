[![Maven Package upon a push](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml/badge.svg?branch=master)](https://github.com/mosip/mimoto/actions/workflows/push-trigger.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mosip_mimoto&id=mosip_mimoto&metric=alert_status)](https://sonarcloud.io/project/overview?id=mosip_mimoto)

# mimoto

## Overview
This repository contains source code for backend service of Inji Mobile and Inji Web. The modules exposes API endpoints.


## Build & run (for developers)
The project requires JDK 21, postgres and google client credentials

### Required Environment Variables

Set the following environment variables before running the application:

| Variable | Description |
|----------|-------------|
| `WALLET_BINDING_PARTNER_API_KEY` | Authenticates requests to the wallet binding partner API |
| `SPRING_DATASOURCE_PASSWORD` | Password to connect to the PostgreSQL database |

Set these using **one** of the following approaches:
- **IDE (IntelliJ / VS Code):** Add them in the run configuration's environment variables section. These persist across IDE restarts.
- **Terminal (Windows):** `set WALLET_BINDING_PARTNER_API_KEY=<your-api-key>` and `set SPRING_DATASOURCE_PASSWORD=<your-db-password>` *(session only — lost when terminal is closed)*
- **Terminal (Linux/Mac):** `export WALLET_BINDING_PARTNER_API_KEY=<your-api-key>` and `export SPRING_DATASOURCE_PASSWORD=<your-db-password>` *(session only — lost when terminal is closed)*

### without docker-compose Build & install
1. Install pgadmin and update application-default.properties file with values
   ```properties
   spring.datasource.username=
   spring.datasource.password=
   ```

2. **Configuring Cache Providers:**

   By default, Mimoto uses Caffeine, a fast in-memory cache. This works well if you're running just one instance of Mimoto.

   But if you're running multiple Mimoto instances (like in Docker Swarm, Kubernetes, or a load-balanced setup), each instance has its own separate cache with Caffeine — they don’t talk to each other.

   In that case, switching to a shared cache like Redis is important. Redis lets all Mimoto instances share the same cached data, which helps keep things consistent and improves performance in distributed setups.

   For detailed setup instructions (including running Redis with Docker CLI and updating configuration), see the [Cache Providers Setup Guide](#cache-providers-setup-guide) section.
      

3. **Configuring Postgres Database:**
   1. **Ensure Postgres Service is Available and Connected**
      - **Using Local Postgres Installation:** If you have Postgres installed locally, run the database initialization scripts:
           ```bash
           cd db_scripts/inji_mimoto
           ./deploy.sh deploy.properties
           ```
        * If needed, update the database connection properties in [application-local.properties](src/main/resources/application-local.properties) with your local Postgres credentials.
      
      - **Using Docker Compose:** If you don't have postgres setup in your local you can run Postgres along with Mimoto by using the `postgres` service in [docker-compose.yml](docker-compose/docker-compose.yml).

      - **Or, run Postgres using Docker while starting Mimoto through your IDE:**
         * Use the following Docker command to start the Postgres service and expose it on the default port 5432. Make sure this port is accessible from your local machine.
            ```bash
                docker pull postgres:latest  # Pull the Postgres image if not already available
                docker run -d --name postgres \
                -e POSTGRES_USER=postgres \
                -e POSTGRES_PASSWORD=postgres \
                -e POSTGRES_DB=inji_mimoto \
                -p 5432:5432 \
                postgres:latest
            ```
         * Start Mimoto normally, following the instructions mentioned in [Build & run (for developers) section](#build--run-for-developers).
   2. **Update the following properties** in
    - [application-local.properties](src/main/resources/application-local.properties) *(when running through IDE)*, or
    - [mimoto-default.properties](docker-compose/config/mimoto-default.properties) *(when running through Docker)*:
   
      **Look for properties starting with:**
   - `spring.datasource.*`
   - `spring.datasource.*`
   - `mosip.mimoto.database.*`
   3. **Check data in postgres by using the following commands**
      ```bash
      docker exec -it postgres psql -U postgres -d inji_mimoto # connect to container
      
      \dt mimoto.* # to see all tables in mimoto schema
      
      SELECT * FROM mimoto.<table_name>; # to see data in a table
      ```

4. Refer to the [How to create Google Client Credentials](docker-compose/README.md#how-to-create-google-client-credentials) section to create
   Google client credentials and update below properties in `application-local.properties`.
    ``` 
    spring.security.oauth2.client.registration.google.client-id=
    spring.security.oauth2.client.registration.google.client-secret=
    ```
5. Add identity providers as issuers in the `mimoto-issuers-config.json` file of [resources folder](src/main/resources/mimoto-issuers-config.json). For each provider, create a corresponding object with its issuer-specific configuration. Refer to the [Issuers Configuration](docker-compose/README.md#mimoto-issuers-configuration) section for details on how to structure this file and understand each field's purpose and what values need to be updated.

6. Add or update the verifiers clientId, redirect and response Uris in `mimoto-trusted-verifiers.json` file of [resources folder](src/main/resources/mimoto-trusted-verifiers.json) for Verifiable credential Online Sharing.

7. Keystore(oidckeystore.p12) Configuration:
   In the root directory, create a certs folder and generate an OIDC client. Add the onboard client’s key to the oidckeystore.p12 file and place this file inside the certs folder.
   Refer to the [official documentation](https://docs.inji.io/inji-wallet/inji-mobile/technical-overview/customization-overview/credential_providers) for guidance on how to create the **oidckeystore.p12** file and add the OIDC client key to it.
   * The **oidckeystore.p12** file stores keys and certificates, each identified by an alias (e.g., mpartner-default-mimoto-insurance-oidc). Mimoto uses this alias to find the correct entry and access the corresponding private key during the authentication flow.
   * Update the **client_alias** field in the [mimoto-issuers-config.json](src/main/resources/mimoto-issuers-config.json) file with this alias so that Mimoto can load the correct key from the keystore.
   * Also, update the **client_id** field in the [same file](src/main/resources//mimoto-issuers-config.json) with the client_id used during the onboarding process.
   * Set the `oidc_p12_password` environment variable in the Mimoto service configuration inside docker-compose.yml to match the password used for the **oidckeystore.p12** file.
   * Update the following properties in applicatio-local.properties file
   ```properties
   mosip.oidc.p12.password=<your-keystore-password>
   mosip.kernel.keymanager.hsm.config-path=<path to the keystore file>
   mosip.kernel.keymanager.hsm.keystore-pass=<your-keystore-password>
    ```
   * Mimoto also uses this same keystore file (oidckeystore.p12) to store keys generated at service startup, which are essential for performing encryption and decryption operations through the KeyManager service.

8. To configure any Mobile Wallet specific configurations refer to the [Inji Mobile Wallet Configuration](docker-compose/README.md#inji-mobile-wallet-configuration) section.

9. Run the SQLs using <db name>/deploy.sh script. from [db_scripts folder](db_scripts/inji_mimoto)
   ```
   ./deploy.sh deploy.properties
   ```

10. Build the jar
    ```
    mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true
    ```

11. Run following command
    ```
    mvn spring-boot:run -Dspring.profiles.active=local
    ```

## Cache Providers Setup Guide

To use Redis (or any other cache provider), the service must be **running** and **accessible to Mimoto**. Both services (cache provider and Mimoto) must be on the same Docker network.  
This can be done by adding them to a shared network in your `docker-compose.yml` file, or by using the following commands if they are running separately.

**Example: Using Redis as Cache Provider**

1. **Ensure Redis Service is Available and Connected:**

   - **Using Docker Compose:** You can run Redis alongside Mimoto by adding the below lines in docker-compose.yml. Docker Compose ensures both services run on the same network automatically.
        1. Add the Redis service under the services section:
            ```yaml
             redis:
               image: redis:alpine
               container_name: 'redis'
               ports:
                 - "6379:6379"
               volumes:
                 - redis-data:/data
             ```
        2. Make Redis a dependency for the Mimoto service:
            ```yaml
             mimoto-service:
               depends_on:
                 - redis
            ```
        3. Add Redis data volume in the volumes section:
            ```yaml
             volumes:
               redis-data:
            ```

   - **Or, run Redis using Docker while starting Mimoto through your IDE:**
      - Use the following Docker command to start the Redis service and expose it on the default port 6379. Make sure this port is accessible from your local machine.
        ```bash
        docker pull redis:alpine # Pull the Redis image if not already available
        docker run -d --name redis -p 6379:6379 redis:alpine  # Start a Redis container named 'redis' and expose it on port 6379
        ```
      - Start Mimoto normally, following the instructions mentioned in [Build & run (for developers) section](#build--run-for-developers).

2. **Update the following properties** in
   - [application-local.properties](src/main/resources/application-local.properties) *(when running through IDE)*, or
   - [mimoto-default.properties](docker-compose/config/mimoto-default.properties) *(when running through Docker)*:
    ```properties
    spring.session.store-type=redis   # Store HTTP sessions in Redis
    spring.cache.type=redis           # Store application data in Redis
    ```

3. **Add and update the required Redis configurations** in
   - [application-local.properties](src/main/resources/application-local.properties) or
   - [mimoto-default.properties](docker-compose/config/mimoto-default.properties), similar to those in the [application-default.properties](src/main/resources/application-default.properties) file.  
     Look for properties starting with:
   - `spring.data.redis.*`
   - `spring.session.redis.*`

4. **Check the cached data of the redis by running the following command:**
    ```bash
    docker exec -it redis redis-cli
   ```

### with docker-compose
1. To simplify running mimoto in local for developers we have added [Docker Compose Setup](docker-compose/README.md). This docker-compose includes mimoto service and nginx service to server static data.
2. Follow the below steps to use custom build image in docker-compose
* Build the mimoto.jar
  ```mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true```
* Build docker image by running the below command in the directory where Dockerfile is present, use any image tag
  ```docker build -t <image-with-tag> .```
* Use newly built docker image in docker-compose file
   
## [Deployment in K8 cluster](deploy/README.md)
   
## Credits
Credits listed [here](/Credits.md)