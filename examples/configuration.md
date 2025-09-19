# Configuration examples

To configure the service, you have different options, which all use the same config-keys:

### Config-File `config.toml`

One option is to use a config-file in `.toml` format, which looks like this:

```toml
ip_addr = "0.0.0.0:8080"
data_dir = "/var/lib/storage"
domain = "https://storage.example.com"
presign_api_key = "I5642qehwRMNDIBEtthjbzWN4uFDdzf6"
presign_hmac_secret = "9RKNSeGVA9F2agDgEkOqzra3EUs320trMkTRMx1AdJ4BE7AoTpzpkPNE0FU9D2yN"
cors_origins = "https://www.example.com,https://api.example.com"
ttl_orphan_secs = 43200
max_data_rq_size = 4294967296     # 4 GiB
max_presign_rq_size = 102400      # 100 KiB
rq_timeout_secs = 30
```

Important note: If you use a config file, you have to specify all keys,
in contrast to the other options, which will use a default value if a key is not present.

### CLI flags

This is the most basic option, and does not give you fine-tuned control to keep the interface simple.

You can only set the three basic required options `ip_addr`, `data_dir` and `domain`:

```
borderless-storage \
  --ip-addr 0.0.0.0:8080 \
  --data-dir /var/lib/storage \
  --domain https://storage.example.com \
  --presign-api-key I5642qehwRMNDIBEtthjbzWN4uFDdzf6 \
  --verbose
```

Note: The verbosity flag is used to increase the log level to `DEBUG`.
This option is parsed *only* via the cmdline and will be used when the service is otherwise configured via config-file or env-variables!

### Environment variables

Another option, which is very useful for docker deployments, is the usage of environment variables.
The keys are identical to the config file, but must be all uppercase. If a value is not present, the service will use a default value instead:

```
# -- required
export IP_ADDR=0.0.0.0:8080
export DATA_DIR=/var/lib/storage
export DOMAIN=https://storage.example.com
export PRESIGN_API_KEY="I5642qehwRMNDIBEtthjbzWN4uFDdzf6"
# -- optional
export PRESIGN_HMAC_SECRET="9RKNSeGVA9F2agDgEkOqzra3EUs320trMkTRMx1AdJ4BE7AoTpzpkPNE0FU9D2yN"
export CORS_ORIGINS="https://www.example.com,https://api.example.com"
export TTL_ORPHAN_SECS=43200
export MAX_DATA_RQ_SIZE=4294967296
export MAX_PRESIGN_RQ_SIZE=102400
export RQ_TIMEOUT_SECS=30
borderless-storage
```

You can still use the `--verbose` flag, if you want to use `DEBUG` logs.

### CORS

Allowed cors origins can be specified via a comma separated list of URLs:

```
export CORS_ORIGINS="https://www.example.com,https://api.example.com"
```

If no allowed origins are specified, all origins are allowed by default.

This is not recommended in production deployments, which is why the service will emit a runtime warning in non-debug builds.

Don't try to use a wildcard ('\*') here, as the config file validation expects all cors origins to be valid urls, just leave the value empty.
