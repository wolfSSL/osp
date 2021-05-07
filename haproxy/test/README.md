# Description

This directory implements some of the `*.vtc` HaProxy reg-tests. These
allow each component to be manually run and examined for errors. Most importantly,
this allows us to plug gdb into the haproxy binary.

The cfg config files were extracted from and correspond to the vtc tests
of the same name found in the reg-tests directory of HaProxy. For example,
the `cfg/ssl_server_samples.cfg` config re-creates the test scenario from
`reg-tests/ssl/ssl_server_samples.vtc`.

- `http-responder.py` - a small http responder server for testing
- `run-haproxy.sh` - wrapper script for running the HaProxy binary

# Running tests

In general, you should run the following in parallel in order:

```
./http-responder.py 10082
HAPROXY_ROOT=/path/to/haproxy/source/dir ./run-haproxy.sh cfg/chosen-config.cfg
curl localhost:10080 -v
```
