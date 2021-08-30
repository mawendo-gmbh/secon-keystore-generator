# SECON KeyStore Generator

[![CI Actions Status](https://github.com/mawendo-gmbh/secon-keystore-generator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mawendo-gmbh/secon-keystore-generator/actions)

This tool generates a PKCS12 key store containing public certificates published by the ITSG Trust Center. The generated key store can for example be used by [Diga API Client](https://github.com/alex-therapeutics/diga-api-client) or [secon-tool](https://github.com/DieTechniker/secon-tool).

## Usage
Download the latest generator release from [here](https://github.com/mawendo-gmbh/secon-keystore-generator/releases) and 
download the latest **annahme-rsa4096.key** file from [ITSG Trust Center](https://www.itsg.de/produkte/trust-center/oeffentliche-zertifikate-und-verzeichnisse/) website ([direct link to key](https://trustcenter-data.itsg.de/dale/annahme-rsa4096.key)).

### Public certificates keystore

Use the following command to generate a key store containing all the public certificatse. It will prompt you for a password which will be used to secure the key store.

```
java -jar secon-keystore-generator-<version>.jar -k <insurance-keys-input-filename> -s <key-store-output-filename>
```

### Public certificates and your private certificate keystore

You can also generate a key store containing all public certificates and also embed your private certificate. 

For example, this could be used as the only certificate file you need to use the [DiGA API Client](https://github.com/alex-therapeutics/diga-api-client).

To do this, you also need these files:
- Your private key. This must be a PKCS1 `.pem` file which only contains the private key. It should start with `-----BEGIN RSA PRIVATE KEY-----` When you created your keys to send to ITSG, you saved this somewhere.
- The certificate chain you received from ITSG. When ITSG approves your certificate application they send you some files. There should be a `.p7c` file there which contains your private certificate chain.

```
java -jar secon-keystore-generator-<version>.jar \\
    -k <insurance-keys-input-filename> \\
    -s <key-store-output-filename> \\
    -p <private-key-filename> \\
    -c <private-certificate-chain-filename>
```

for example
```
java -jar secon-keystore-generator.jar -k annahme-rsa4096.key -p my.prv.key.pem -c my.chain.p7c
```
will prompt you for a password, and generate a file called `certificates.p12` which contains all public certificates
as well as your private certificate with the alias `private`.

#### Alternative private key format

In case you have problems loading the private key, it might help to convert your `my.prv.key.pem` into PKCS8 format before using this tool:

```bash
# Convert key
openssl pkcs8 -topk8 -inform PEM -outform DER -in my.prv.key.pem -out my.prv.key.der -nocrypt

# Use pkcs8 key to create the certificates.p12 file
java -jar secon-keystore-generator.jar -k annahme-rsa4096.key -p my.prv.key.der -c my.chain.p7c
```

## License
MIT
