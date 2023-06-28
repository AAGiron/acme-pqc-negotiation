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

# Introduction

The Automated Certificate Management Environment (ACME) is defined in RFC 8555 [RFC8555]. ACME automates X.509 certificate issuance for Web Servers, thus easing the configuration process in providing encrypted channels over the Internet, often by using HTTPS/TLS protocols. Backed by the Let's Encrypt project, ACME has contributed to a secure Internet by giving the opportunity for system administrators and developers to secure their websites easily and free. ACME specifies how an ACME client can request a certificate to an ACME server with automation capabilities. The server requires a "proof" that the client holds control of the web server's identifier (often a domain name). After this validation process, the server can issue one or more "Domain Validated" (DV) certificate(s) so the client can configure an HTTPS server for the particular domain name(s). 

Basically, ACME requires three steps for the clients when issuing a certificate. First, a client creates an anonymous account to the desired ACME server. Note, however, that it is assumed that the client already trust in the ACME server's certificate, otherwise the client can not connect to the server securely. A secure channel between ACME peers is a requirement fulfilled often by a TLS connection, thus the client must trust in the certificate chain provided by the ACME server. Secondly, after creating an account, the ACME server must prove the ownership of an identifier (i.e., domain name) by means of an ACME challenge. Currently, HTTP-01, DNS-01 and TLS-ALPN-01 are standardized by IETF (others are being proposed, e.g., [draft token for telephony]. Lastly, after proving the control of the identifier, the client request a certificate by sending a Certificate-Signing Request (CSR) to the ACME server. The server validates the request and the CSR. If everything went ok, the client can download the requested certificate(s). Note the sequential process: account creation, challenge validation, and then requesting/issuing the certificate.

In order to request and issue a certificate, ACME specification obligates implementations to support elliptical curve algorithm "ES256" [RFC7518] and state that they should support  the "Ed25519" algorithm [RFC8037]. Since the messages in ACME follows the JSON Web Signature standard [JWS], the algorithm support details are specified outside ACME. Therefore, if an ACME server does not support the algorithm or a particular parameter that the client has requested, the server throws "badPublicKey", "badCSR" or "badSignatureAlgorithm" (RFC 8555, Section 6.7). It is worthy to note that, accordingly to  [cloudflare CT log viewer], "RS256" algorithm is dominant in DV certificates.

The main problem caused by the absence of an algorithm negotiation procedure in ACME is that clients does not know in advance if the server has support to a particular algorithm for the certificate. Therefore, the client must create an account, perform the validation, send a CSR and then receive an error ("badPublicKey"). This "trial-and-error" process  spends client and server resources inefficiently. Having an algorithm negotiation process, the client could check several ACME servers until the client finds the support it needs, without wasting time creating an account and validating the domain for each one of the servers. 

Currently, the NIST is selecting Post-Quantum Cryptography (PQC) algorithms for standardization [NISTPQC]. Dilithium (primary), Falcon, and Sphincs+ have been selected, but other signature algorithms may appear. Similarly, Kyber was selected for standardization as a Key Encapsulation Mechanism (KEM), but others are still candidates (BIKE, HQC, Classic McEliece). Some of these algorithms are probably going to replace the classical alternatives, such as "RS256" and "ES256", since the latter are known to be vulnerable to a Cryptographically Relevant Quantum Computer [CRQC, MoscaAndPiani]. The PQC algorithms have several parameters, not to mention the "hybrid mode", combining them to the classical alternatives, e.g., in dual signatures [NISTDualSignatures]. One can expect that, in the near future, ACME clients will chose the best PQC algorithm (and the mode) that better suit its needs.  Consequently, the HTTPS/TLS servers will be able to secure their connections against the quantum threat. 

In the PQC migration context, TLS has a promising alternative called KEMTLS [KEMTLS]. KEMTLS replaces digital signatures in TLS handshakes by using a KEM algorithm. Therefore, a KEMTLS server must have a KEM certificate: a digital certificate containing the web server's KEM public key and a signature provided by the CA. As of now, ACME does not support KEM algorithms for certificates.


This document describes an algorithm negotiation procedure for ACME. The process gives flexibility for ACME clients to select the certificate algorithm that better fits its needs, with the PQC landscape options in mind. The document also specifies options for  ACME peers when negotiate a KEM certificate issuance, with or without a CSR-like process, thus contributing to the KEMTLS adoption.

# Certificate Algorithm Negotiation

TODO text (API endpoints)

# KEM Certificate Issuance

TODO Text, Figures

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
