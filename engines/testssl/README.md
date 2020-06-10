## Description
TestSSL Engine alpha version

do not use in production environment

https://testssl.sh/

## Dependencies
- Python 3 + pip
- See requirements.txt for others python packages (use "pip3 install -r requirements.txt")


## Findings
#### Server configurations
- Supported ciphers: SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3, ALPN
- Session ticket duration
- Multi-certificate support (eg ECDSA/RSA)
- Ciphers enumeration
#### Certificate properties
- Signature algorithm
- Certificate key size
- Certificate SHA256 fingerprint
- Certificate CommonName
- Certificate Issuer
- Certificate EV
- OCSP stapling
- Certificate transparency

#### Vulnerabilities
- Heartbleed
- ChangeCipherSpec
- Ticketbleed
- ROBOT
- Secure Renegociation
- Client Secure Renegociation
- CRIME Tls
- BREACH
- PODDLE
- fallback SCSV
- SWEET32
- FREAK
- DROWN
- LOGJAM
- BEAST
- LUCKY13
- RC4



## Todo:
- [ ] improve cipher list
- [ ] set severity/info/solution
