# js-srp
This is an implementation of the SRP-6a protocol with modifications to provide compatibility with [opencoff/go-srp](https://github.com/opencoff/go-srp). These differences are quoted here, from the [opencoff/go-srp README](https://github.com/opencoff/go-srp#differences-from-srp-6a-and-rfc-5054).

> Differences from SRP-6a and RFC 5054
>
> We differ from the SRP-6a spec and RFC 5054 in a couple of key ways:
>
> - We hash the identity I; this provides some (minimal) protection against dictionary attacks on the username.
> - We hash the user passphrase p; this expands shorter passphrase into longer ones and extends the alphabet used in the passphrase.
> - We differ from RFC 5054 in our choice of hash function; we use Blake-2b. SHA-1 is getting long in the tooth, Blake2b is the current state-of-the art. Equivalently, one may use SHA3 (see below for using a user supplied hash function).

The only difference is that Blake2b is not supported because it is not offered by WebCrypto; instead, you can choose between the overlapping supported hash functions between opencoff/go-srp and WebCrypto.

Currently, only client functionality is implemented.

This library does not have any external runtime dependencies. It requires a JavaScript runtime that supports w3c Typed Arrays, BigInt, and WebCrypto, which includes the majority of web browsers and JavaScript engines.
