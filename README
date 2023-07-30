# Internet-Draft for PQC Algorithm Negotiation in ACME

The ACME protocol (RFC 8555) depends on other RFCs for negotiating cryptography algorithms:
- TLS (RFC 8446) for a secure channel between the ACME parties (client, server)
- ACME Client's Account Keys for signing requests (JSON Web Signatures: RFC 7515)
- ACME Client's Certificate keys: RFC 8555 states that implementors must support "ES256" (RFC7518) and that they should support the "Ed25519" algorithm (RFC8037)
- ACME Server Certificate chain: through a functionality called "Preferred chain", clients can choose  (by name) the desired Issuer Certificate Authority (CA) to be part of the requested certificate. The server uses a default certificate chain when issuing the client's certificate if unavailable.  

## Why add Algorithm negotiation in ACME?

In light of Post-Quantum Cryptography (PQC), many signature algorithm alternatives can be used, allowing for different trade-offs (e.g., signature vs. public key size). For a future ACME, negotiating certificate algorithms would give clients more flexibility. The main reasons are:
- In the short term, clients could ask for classical, hybrid, or PQC certificates. Hybrid means a combination of classical and PQC algorithms. 
- Considering PQC adoption strategies, one could ask for a certificate using keys from a PQC signature scheme, enabling PQTLS servers (which would not require protocol changes in ACME). However, one could desire keys from a Key-Encapsulation Mechanism (KEM), enabling [KEMTLS](https://dl.acm.org/doi/abs/10.1145/3372297.3423350) servers, which could reduce communication costs (in bytes). *ACME currently does not support KEM certificate issuance*, because there is no Certificate *Signing* Request (CSR) from a KEM. One alternative is to use Verifiable Generation by [Güneysu et al., 2022](https://dl.acm.org/doi/abs/10.1145/3548606.3560560) so a KEM can be fit in a CSR-like process. One drawback is the increased sizes.    
- Lastly, algorithm negotiation in ACME could improve *efficiency*: a client wants a particular algorithm in the certificate, so it creates an account with the server, ask for a challenge (e.g., HTTP-01), performs the challenge, ask for the server to validate that challenge, and after all that, ask for a certificate using the keys from the desired algorithm. If the server does not support the algorithm  (i.e., throwing "BadPublicKey"), or the client selects another algorithm, or all the work is lost, wasting computational resources on both sides. 

Considering the above, ACME could be improved by providing algorithm negotiation at the protocol's beginning. Therefore, ACME clients could know if the server supports the desired certificate algorithm. Moreover, ACME could be modified to accommodate automated KEM certificate issuance, which contributes not only to ACME but also to the adoption of the KEMTLS protocol.

## Features

This RFC informs implementors of a way to add, in ACME, the following features:
- Algorithm Negotiation considering PQC and its different strategies (e.g., hybrids, KEMTLS, KEM-POP); and
- Two modes to issue KEM certificates (assuming server support has been confirmed earlier using the above feature).

Contributions are welcome!
