dcos-auth-proxy
===

[![Build Status](https://travis-ci.org/matt-deboer/dcos-auth-proxy.svg?branch=master)](https://travis-ci.org/matt-deboer/dcos-auth-proxy)

A simple authenticating proxy for DCOS that allows you to expose Marathon, Metronome, and other
DCOS protected APIs on a local port such that authentication is automatically handled by the proxy.

Motivation
---

To ease integration with Mesos for apps that are unaware of the DCOS authentication and secrets architecture.

Usage
---

- Bundle the go binary within your docker container
- Map in the `principal secret` that will be used for authentication
- Launch the proxy as a background task, providing a `target-url` and the `principal-secret`

_Notes_:
  - by default, the proxy only listens on `localhost`; it is not recommended to expose the proxy externally, but the host interface can be configured via the `--host` parameter
  - pass `-V` or `--verbose` for extra output; the proxy only logs errors by default
Example
---

  ```
  dcos-auth-proxy -t https://my-dcos.example.org/marathon -p 8888 -s $MARATHON_CLIENT_SECRET
  ```


Building
---
  ```
  make
  ```
  - _places binary at `bin/dcos-auth-proxy`_