# Kubernetes service account integration for Eclipse Mosquitto

## Overview

This experimental plugin provides the option for `mosquitto` clients to authenticate with a Kubernetes service account.

It provides two authentication options:

  - Username/password: for use with off-the-shelf MQTT integrations and 3rd-party applications.
  - Service account tokens: use K8S-native short-term credentials to authenticate, at the cost of having to 
    rig the MQTT clients to support this (which can be done in several ways depending on circumstances).

When authenticating as a service account, set the username string to `__token__` and pass the token
as the password.

## Acknowledgements

This experiment started out as an amalgamation of the following projects:

  - https://github.com/iegomez/mosquitto-go-auth
  - https://github.com/gewv-tu-dresden/mosquitto-go-auth-oauth2

...but ended up going in a somewhat different direction after several rounds of refactoring and simplification.
It nonetheless still draws heavily upon these projects.

## Service account example

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    # Comma-separated list of topics to which the account has read access
    mqtt.dev.mvalvekens.be/allow-read: foo/#,bar/baz/quux
    # Comma-separated list of topics to which the account has write access
    mqtt.dev.mvalvekens.be/allow-write: foo/#,zzz
    # Secret containing the password for this user in `MQTT_PASSWORD`.
    # If this annotation is omitted, only token-based authentication will be allowed.
    mqtt.dev.mvalvekens.be/password-secret: testuser-creds
  name: testuser
  namespace: iot
automountServiceAccountToken: true
```

## Limitations

  - Currently, this plugin only works when the `mosquitto` instance is itself running in Kubernetes. The pod
    needs to be associated with a service account that can access the `TokenReview` API, and has the ability
    to read `ServiceAccount` and `Secret` resources in the namespace on which it operates.
  - The plugin only looks at service accounts in one namespace (by default, the one in which it is currently deployed)
