# mimoto-apitestrig

Helm chart to deploy APITESTRIG (API test rig) for INJI `mimoto` as a Kubernetes CronJob.

This chart was previously consumed from `mosip/apitestrig` (mosip-functional-tests) and is now maintained in this repository.

## Install
```console
$ cd ../../deploy/mimoto-apitestrig
$ ./install.sh
```

Or directly:
```console
$ helm dependency update helm/mimoto-apitestrig
$ helm -n injiweb install mimoto-apitestrig helm/mimoto-apitestrig -f deploy/mimoto-apitestrig/values.yaml
```

## Key values
| Parameter | Description | Default |
|---|---|---|
| `modules.mimoto.image.repository` | apitest-mimoto image | `injistackdev2/apitest-mimoto` |
| `modules.mimoto.image.tag` | apitest-mimoto image tag | `release-1.0.x` |
| `crontime` | Cron schedule | `0 3 * * *` |
| `apitestrig.configmaps.apitestrig.*` | Values for the `apitestrig` configmap (ENV_USER, ENV_ENDPOINT, ENV_TESTLEVEL, eSignetDeployed, ...) | |
| `apitestrig.variables.push_reports_to_s3` | Push reports to S3 (`yes`) or to an NFS-backed PVC (`no`) | `yes` |
| `enable_insecure` | Add init container that trusts the server's self-signed certificate | `false` |
| `cacertsMountPath` | Where the generated cacerts is mounted when `enable_insecure` is true | `/usr/local/openjdk-11/lib/security/cacerts` |
