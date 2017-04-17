relic is a multi-tool and server for package signing and working with PKCS#11 hardware security modules (HSMs).

It can sign these package types:

* RPM
* DEB
* JAR
* PE/COFF - Windows executable
* MSI
* appx, appxbundle - Windows universal
* CAB - Windows cabinet file
* CAT - Windows security catalog
* XAP - Silverlight and legacy Windows Phone applications
* PS1, PS1XML, MOF, etc. - Microsoft Powershell script
* .manifest, .application - Microsoft ClickOnce manifest
* PGP - detached or cleartext signature of data

Relic can also operate as a signing server, allowing clients to authenticate
with a TLS certificate and sign packages remotely.

Other features include:

* Generating and importing keys in the token
* Importing certificate chains from a PKCS#12 file
* Creating X509 certificate signing requests (CSR) and self-signed certificates
* Creating simple PGP public keys
* RSA and ECDSA supported for all signature types
* Verify signatures on all supported package types
* Sending audit logs to an AMQP broker
* Save token PINs in the system keyring

Linux and Windows are supported. Other platforms probably work as well.

To install relic:

    go get gerrit-pdt.unx.sas.com/tools/relic.git/relic

See distro/linux/relic.yml for an example configuration.
