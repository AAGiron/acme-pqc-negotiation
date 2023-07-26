---
###
#  draft-giron-acme-pqc-negotiation-00

title: "ACME PQC Algorithm Negotiation"
abbrev: "acme-pqc-algo-neg"
category: info

docname: draft-giron-acme-pqc-negotiation-00
submissiontype: independent
number:
date:
v: 0
area: None
workgroup: None
keyword:
 - Automated Certificate Management Environment
 - X.509 Certificates
 - Post-Quantum Cryptography 
venue:
  group: N/A
  type: -
  mail: -
  arch: -
  github: TBD
  latest: -

author:
 -
    fullname: Alexandre Augusto Giron
    organization: Federal University of Technology - Parana (UTFPR)
    email: alexandregiron@utfpr.edu.br

normative:

informative:


--- abstract

ACME is a critical protocol for accelerating HTTPS adoption on the Internet, automating digital certificate issuing for web servers. Because RFC 8555 assumes that both sides (client and server) support the primary cryptographic algorithms necessary for the certificate, ACME does not include algorithm negotiation procedures. However, in light of Post-Quantum Cryptography (PQC), many signature algorithm alternatives can be used, allowing for different trade-offs (e.g., signature vs. public key size). In addition, alternative PQC migration strategies exist, such as KEMTLS, which employs KEM public keys for authentication. This document describes an algorithm negotiation mechanism for ACME. The negotiation allows different strategies and provides KEMTLS certificate issuing capabilities.


--- middle

# 1 Introduction

The Automated Certificate Management Environment (ACME) is defined in RFC 8555 [RFC8555]. ACME automates X.509 certificate issuance for Web Servers, thus easing the configuration process in providing encrypted channels over the Internet, often by using HTTPS/TLS protocols. Backed by the Let's Encrypt project, ACME has contributed to a secure Internet by giving the opportunity for system administrators and developers to secure their websites easily and free. ACME specifies how an ACME client can request a certificate to an ACME server with automation capabilities. The server requires a "proof" that the client holds control of the web server's identifier (often a domain name). After this validation process, the server can issue one or more "Domain Validated" (DV) certificate(s) so the client can configure an HTTPS server for the particular domain name(s). 

Basically, ACME requires three steps for the clients when issuing a certificate. First, a client creates an anonymous account to the desired ACME server. Note, however, that it is assumed that the client already trust in the ACME server's certificate, otherwise the client can not connect to the server securely. A secure channel between ACME peers is a requirement fulfilled often by a TLS connection, thus the client must trust in the certificate chain provided by the ACME server. Secondly, after creating an account, the ACME server must prove the ownership of an identifier (i.e., domain name) by means of an ACME challenge. Currently, HTTP-01, DNS-01 and TLS-ALPN-01 are standardized by IETF (others are being proposed, e.g., [draft token for telephony]. Lastly, after proving the control of the identifier, the client request a certificate by sending a Certificate-Signing Request (CSR) to the ACME server. The server validates the request and the CSR. If everything went ok, the client can download the requested certificate(s). Note the sequential process: account creation, challenge validation, and then requesting/issuing the certificate.

In order to request and issue a certificate, ACME specification obligates implementations to support elliptical curve algorithm "ES256" [RFC7518] and state that they should support  the "Ed25519" algorithm [RFC8037]. Since the messages in ACME follows the JSON Web Signature standard [JWS], the algorithm support details are specified outside ACME. Therefore, if an ACME server does not support the algorithm or a particular parameter that the client has requested, the server throws "badPublicKey", "badCSR" or "badSignatureAlgorithm" (RFC 8555, Section 6.7). It is worthy to note that, accordingly to  [cloudflare CT log viewer], "RS256" algorithm is dominant in DV certificates.

The main problem caused by the absence of an algorithm negotiation procedure in ACME is that clients does not know in advance if the server has support to a particular algorithm for the certificate. Therefore, the client must create an account, perform the validation, send a CSR and then receive an error ("badPublicKey"). This "trial-and-error" process  spends client and server resources inefficiently. Having an algorithm negotiation process, the client could check several ACME servers until the client finds the support it needs, without wasting time creating an account and validating the domain for each one of the servers. 

Currently, the NIST is selecting Post-Quantum Cryptography (PQC) algorithms for standardization [NISTPQC]. Dilithium (primary), Falcon, and Sphincs+ have been selected, but other signature algorithms may appear. Similarly, Kyber was selected for standardization as a Key Encapsulation Mechanism (KEM), but others are still candidates (BIKE, HQC, Classic McEliece). Some of these algorithms are probably going to replace the classical alternatives, such as "RS256" and "ES256", since the latter are known to be vulnerable to a Cryptographically Relevant Quantum Computer [CRQC, MoscaAndPiani]. The PQC algorithms have several parameters, not to mention the "hybrid mode", combining them to the classical alternatives, e.g., in dual signatures [NISTDualSignatures]. One can expect that, in the near future, ACME clients will chose the best PQC algorithm (and the mode) that better suit its needs.  Consequently, the HTTPS/TLS servers will be able to secure their connections against the quantum threat. 

In the PQC migration context, TLS has a promising alternative called KEMTLS [KEMTLS]. KEMTLS replaces digital signatures in TLS handshakes by using a KEM algorithm. Therefore, a KEMTLS server must have a KEM certificate: a digital certificate containing the web server's KEM public key and a signature provided by the CA. As of now, ACME does not support KEM algorithms for certificates.

This document describes an algorithm negotiation procedure for ACME. The process gives flexibility for ACME clients to select the certificate algorithm that better fits its needs, with the PQC landscape options in mind. The document also specifies options for  ACME peers when negotiate a KEM certificate issuance, with or without a CSR-like process, thus contributing to the KEMTLS adoption.

# 2 Certificate Algorithm Negotiation

In order to allow ACME client implementations to select their preferred certificate algorithm set, this document specifies servers to implement a new endpoint named /cert-algorithms. The new endpoint can be reached after a GET /dir (see Figure 1 below). The client does not need to create an account with the server, thus saving resources. As PQC standardization evolves, this document does not specify one default configuration or algorithm. ACME implementations can select their preferred (or default) configurations, but they should also allow users to choose at least in the first certificate issuance (renewals can be automated with the same configuration). 

```
 +------+                       +------+
 | ACME |                       | ACME |
 |Client|                       |Server|
 +--+---+                       +--+---+
    |    GET /dir                  |
    |----------------------------->|
    +------------------------------+
    |                   HTTP 200   |
    |                              |
    |    GET /new-nonce            |
    |----------------------------->|
    |<-----------------------------+
    |                   HTTP 200   |
    |                              |
    |    GET /cert-algorithms      |
    |----------------------------->|
    |<-----------------------------+
    |                   HTTP 200   |


Figure 1: Obtaining algorithm support information
```


## 2.1 Issuance processes for KEM Certificates

Depending on the server's support, the server might implement one or several classical, PQC, and hybrid PQC algorithms for certificates. In this context, hybrid algorithms are often called "composite" [Ounsworth draft], in which cryptographic objects are concatenated in a single structure. If the algorithm supported by the server is a signature algorithm, the server replies with the corresponding OID; this is the same as if hybrids are allowed (assuming the composite model and corresponding OIDs [Ounsworth draft]). However, at the time of this writing, ACME does not issue KEM certificates. 

On the other hand, Güneysu et al. showed how to build a CSR-like process to issue a KEM certificate [Güneysu et al., 2022]. In theory, ACME could use such a method to issue a KEM certificate without significant changes at the protocol level. However, PoP using verifiable generation for KEMs has some drawbacks:
- So far, the method is proposed for Kyber and FrodoKEM only. Although the method can also be applied to other algorithms, the security proofs are on a "per-algorithm" basis. 
- The method increase sizes, consequently increasing the communication cost for the ACME's protocol.  

The emphasis of this document is on the KEMTLS certificate use case. KEMTLS aims to reduce the size of cryptographic objects for the PQC migration context. KEMTLS can reduce byte costs for a post-quantum TLS but at the cost of increasing sizes in ACME by using verifiable generation processes. Therefore, in this document, we define a KEMTLS certificate (the subject's public key is a KEM public key, but the Issuer CA signs it) and specify how the ACME protocol could issue such a certificate, considering its performance. 

## 2.2 Algorithm List Definition

Upon GET requests to the /cert-algorithms endpoint, ACME servers reply with a JSON-formatted list of supported algorithms, as follows:

```
{
     "Signatures": {
       "Dilithium2": "1.3.6.1.4.1.2.267.7.4.4",
       "P256_Dilithium2": "1.3.9999.2.7.1",
       "Dilithium3" : "1.3.6.1.4.1.2.267.7.6.5",
        ...
     },
     "KEMTLS": {
       "Kyber-512-with-Dilithium2-sha256": "Kyber-512-with-Dilithium2-sha256",
       "P256-Kyber-512-with-P256-Dilithium2-sha256": "P256-Kyber-512-with-P256-Dilithium2-sha256"
       ...
     },
     "KEM-POP" : {
       "Kyber": "Reserved-TBD",
       "FrodoKEM" : "Reserved-TBD",
     }
}
```

Servers MUST provide such a list with at least one algorithm. Note the distinction between Signatures, KEMTLS, and KEM-POP, as an alternative to telling the clients a different naming to support (possibly) different issuance processes. Moreover, the OIDs presented on this list are from the OQS project [Stebila and Mosca, 2016], but they are subject to change whenever the Internet drafts evolve (such as [Ounsworth draft]).

# 3 KEM Certificate Issuance Modes

ACME Certificate issuance process does not require modifications when issuing PQC signature certificates. However, this document proposes the following changes to the ACME protocol for KEM certificates. Assuming that the ACME client has already performed account registration and challenge, Figures 2 and 3 show two ways to issue a KEM certificate. Figure 2 requires 3 RTTs, while Figure 3 optimizes performance to 1 RTT. The main difference is that the optimized mode does not guarantee key confirmation. Therefore, the ACME server should enforce the 3-RTT mode if it is required to confirm that the client actually possesses the certificate's private key. If performance is desired, the 1-RTT mode is suitable since it reduces the number of signed requests and polling time.

```
     +------+                       +------+                    +------+                       +------+
     | ACME |                       | ACME |                    | ACME |                       | ACME |
     |Client|                       |Server|                    |Client|                       |Server|
     +--+---+                       +--+---+                    +--+---+                       +--+---+
        |                              |                           |                              |
        |pk,sk <- KEM.Keygen()         |                           |pk,sk <- KEM.Keygen()         |
        |                              |                           |                              |
        | POST /finalize [pk,mode]     |                           | POST /finalize [pk,mode]     |
        |----------------------------->|                           |----------------------------->|
        |                              |                           |                              |
        |        Z,ct <- KEM.Encaps(pk)|                           |        Z,ct <- KEM.Encaps(pk)|
        |  ct                          |                           |        enc_cert <-enc(Z,cert)|
        |<-----------------------------+                           | ct,enc_cert                  |
        |                              |                           |<-----------------------------+
        |Z <- KEM.Decaps(ct,sk)        |                           |                              |
        |                              |                           |Z <- KEM.Decaps(ct,sk)        |
        | POST /key-confirm [Z]        |                           |cert <- dec(Z,enc_cert)       |
        |----------------------------->|                           |                              |
        |<-----------------------------+
        |                   HTTP 200   |
        |                     or 401   |
        | POST /certZ                  |                   [ ] Message signed by the client's account
        |----------------------------->|                       key
        |<-----------------------------+
        |           application-pem    |

Figure 2: 3-RTT KEMTLS Certificate Issuance Process        Figure 3: 1-RTT KEMTLS Certificate Issuance Process
```

Figure 2 shows the 3-RTT mode. The client can not use a CSR for a KEMTLS certificate, so it generates a key pair and send a "modified CSR", where the public key is a KEM public key, and the signature is random (dummy) data. The server then identifies and extracts the mode and the KEM public key from the modified CSR. Having implemented the KEM algorithm, the server encapsulates under the client's public key sending back the ciphertext to the client. The client performs a decapsulation and confirms the shared secret using the /key-confirm endpoint. ACME servers willing to issue KEMTLS certificates MUST implement this endpoint. 

Figure 3 shortens the KEMTLS process because it replies a ciphertext and the encrypted certificate before key confirmation. Since it is encrypted, clients without the private key cannot use the certificate. Having the private key, the client decapsulates the shared secret Z and derives a symmetric key from it (see Section 3.2). The symmetric key is used to decrypt the certificate. In this way, issuing a KEMTLS certificate does not impose additional RTTs compared to the 1-RTT CSR standard process, i.e., POSTing a CSR to /finalize. The 3-RTT mode, on the other hand, imposes the RTT related to the key-confirmation endpoint.   

Note, however, that key confirmation can be addressed differently in the 1-RTT mode. First, ACME servers could limit the use of this mode or ask for a delayed key confirmation, depending on CA policies (see Section 5 for a discussion). Secondly, if required, ACME servers could establish a TLS handshake with the client's domain at a later (perhaps more convenient) moment. A valid TLS handshake would tell that the client could use the encrypted certificate, thus proving possession of the private key. Lastly, for the applications where it is enough to prove possession of the account's private key (and not the certificate), the 1-RTT mode could be used. 


## 3.1 POST Examples

Considering the first POST to /finalize (Figure 2), which would be similar to a standard POST [RFC 8555], an example of a reply would be as follows. This example considers a CSR built with a KEM public key (Kyber-512) and dummy data in the CSR's signature.

```
HTTP/1.1 200 OK
Content-Type: application/json
Replay-Nonce: CGf81JWBsq8QyIgPCi9Q9X
Link: <https://example.com/acme/directory>;rel="index"
{
  "key-confirm-data": {
    "ct": "9HwLdArXTDC/otcTWNWYcOgRxWOeUahZj3Ri7SrKlCo4syv...Cl79urEXkhoUhWcqWzb2",
    "ct-alg": "Kyber-512"
  },
  "key-confirm-url": "https://example.com/key-confirm/Rg5dV14Gh1Q"
}
```

Note that this reply contains the 'key-confirm-data' and 'key-confirm-url' so ACME clients can proceed accordingly. After decapsulating the shared secret from "ct", the client can POST to the key confirm URL.

```
POST /key-confirm/Rg5dV14Gh1Q HTTP/1.1
Host: example.com
Content-Type: application/jose+json

{
     "protected": base64url({
       "alg": "Dilithium2",
       "kid": "https://example.com/acme/acct/evOfKhNU60wg",
       "nonce": "Q_s3MWoqT05TrdkM2MTDcw",
       "url": "https://example.com/key-confirm/Rg5dV14Gh1Q"
     }),
     "payload": base64url({
       "Z": "r0Sk+fqvfceIetPIdszNs7PMylb3G/B536mZDj0B8Rs="
     }),
     "signature": "9cbg5JO1Gf5YLjjz...SpkUfcdPai9uVYYQ"
}
```

The POST is signed with Dilithium2 in this example. Note that the client is sending "Z" back in a secure channel (i.e., an underlying TLS connection between the ACME peers), so Z is not being disclosed to a passive attacker. The shared secret Z is used to prove the private key's possession. The ACME server compares the received Z with the order's information and starts issuing the certificate. If Z mismatches the server's storage, an HTTP error 401 is sent. If Z matches, there are no further modifications in the protocol, so the client and server proceed as RFC 8555 [RFC 8555] dictates, i.e., clients start polling until their certificates are ready to be downloaded. 

## 3.2 Encrypting a KEM Certificate

TODO:
- Key derivation function for Z. 
- Symmetric algorithms specs for encrypting the certificate.

# 4 Conventions and Definitions

{::boilerplate bcp14-tagged}


# 5 Security Considerations

TODO:
- Security (CA policies; key confirmation, proof-of-possession assumption on the 1-RTT mode)
- Not verifying the CSR in the 3-RTT mode for compatibility purposes (like GREASE mode); servers might try to instantiate CSR objects  from the POST request data. Random (dummy) data would avoid breaking implementations.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
