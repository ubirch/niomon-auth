# Niomon Auth Microservice

Niomon authorization microservice. It delegates the credentials to some other service to check if the request is authorized. The services currently include:

* cumulocity
* ubirch-internal keycloak
* ubirch-token manager

## Development

The main microservice class is [MessageAuthMicroservice](./src/main/scala/com/ubirch/messageauth/MessageAuthMicroservice.scala),
but [AuthCheckers](./src/main/scala/com/ubirch/messageauth/AuthCheckers.scala) is more interesting, as it contains the
actual auth logic for different services.

# Core Libraries

* sttp
* cumulocity java-client
* ubirch-token-sdk