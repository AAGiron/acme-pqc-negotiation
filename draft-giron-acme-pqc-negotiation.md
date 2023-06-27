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

TODO Introduction


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
