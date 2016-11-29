dcos-auth-proxy
===

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

