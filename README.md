# Nile
Nile is a transport-agnostic message integrity and security implementation. It is designed to act as the proving grounds for a protocol ensuring guaranteed message integrity between services in a micro-service environemnt, regardless of communication method. The name refers to the Nile river as a singluar shipping lane, representing this protocol's use of a singular message channel.


**This project is still under development and brainstorming, and is likely to change dramatically. Constructive input is welcome and appreciated!**


## Theory
In a microservice environment, many services are likely not exposed to the public internet. Communication between those services and the public services is not always handled over https, due to the common practive of terminating https connections at the load balancer. However, there is still a need for trust between these services. The goal here is to establish a protocol for trusted communication which can be sent and received over http, https, grpc, ipc, websockets, etc. The current method for doing so using JSON Web standards, via the [`jose`](https://github.com/panva/jose) library.

## Proposed message flow
1. Two or more services are running in a cluster, and each has been assigned an `id` and a keypair (current implementation uses ECDSA, but RSA support is planned as well)
2. Both services register their public key in [`JWK` format](https://tools.ietf.org/html/rfc7517) with a `PhonebookService`. By default, this is running alongside the first service, but it can also be run as a separate service, and use shared storage (like redis), or some decentralized consensus service. Registration is described in detail later.
3. When service `Alice` wishes to send a message to service `Bob`, `Alice` calls the phonebook service to get `Bob`'s public key.
4. `Alice` serializes her message, and encrypts it in JWE format using that public key.
5. The resulting [`JWE`](https://tools.ietf.org/html/rfc7516) string is treated as the body of a [`JWS`](https://tools.ietf.org/html/rfc7515), which is then signed using `Alice`'s private key.
6. The `JWS` string returned from that process is sent to `Bob` over the communication protocol of choice. This can be nearly anything which allows strings to be sent, but MUST also allow including `Alice`'s id alongside the signed message.
7. `Bob` receives the message from `Alice` with her id included.
8. `Bob` looks up the public key registered to her id.
9. `Bob` uses that public key to verify the signed message is in-fact sent by `Alice`
10. The message is decoded and the internal `JWE` is decrypted using `Bob`'s private key.

By using both Signing and Encrypting, `Bob` can be sure the message is from a trusted sender, and unmodified before decrypting. By using asymmetric encryption on the body, Bob can be sure no other listeners could read the message in-flight. These combined allow complete trust between services.

_note: there is debate on whether the message should be signed before or after encryption. It is possible the order will be reversed in the near future_

## Phonebook
The phonebook service provides truly public listings of registered keys. Acceptance into the phonebook requires proof-of-ownership of both keys in the keypair. This helps to prevent impersonators or man-in-the-middle attacks.

### Registration
To register a public key, you must provide to the phonebook an `id` representing your service, and a `JWS` containing your public key and thumbprint, signed using the corresponding private key. The phonebook will decode the `JWS` in an untrusted manner, by base64 decoding the payload portion of the string. From that untrusted payload, it will read the public key, and attempt to use it to verify the original `JWS`. If the signature is valid, the service knows the sender controls both that public key, and the corresponding private key. The key and a calculated thumbprint are stored in the phonebook for retrieval by other services.

### Implementations
In the base library (this repo), two implementations of the phonebook service are planned:
1. The `InMemoryPhonebook` - This is the default phonebook implementation, and it stores all its known keys in-memory on the running host. This host-service could then be used by other services.
2. `FileSystemPhonebook` - Similar to the `InMemoryPhonebook`, this runs on the local host, but saves and loads its data to the filesystem via a configurable filepath. This allows registered keys and known hosts to persist across service restarts.

Other libraries will be created to add additional implementations. a `RemoteHttpPhonebook` (which gets data from another running phonebook via http), and `RedisPhonebook` (which utilizes a shared redis store for keystorage) are already in the works.


## Development Tasks
- [x] Create method for generating `JWK`s
- [x] Create methods for computing signatures
- [x] Create methods for encrypting data
- [x] Add a manager for a service's own keypair
- [x] Define models for messages
- [x] Define dataflow
- [x] `InMemoryPhonebookService`
- [x] `FileSystemPhonebookService`
- [ ] Create express/node middleware
- [ ] Write tests for various services
- [ ] Evaluate security of approach
