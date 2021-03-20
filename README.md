# SECON KeyStore Generator

[![CI Actions Status](https://github.com/mawendo-gmbh/secon-keystore-generator/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mawendo-gmbh/secon-keystore-generator/actions)

This tool generates a PKCS12 key store containing public certificates published by the ITSG Trust Center. The generated key store can for example be used by [Diga API Client](https://github.com/alex-therapeutics/diga-api-client) or [secon-tool](https://github.com/DieTechniker/secon-tool).

## Usage
Download the latest generator release from [here](https://github.com/mawendo-gmbh/secon-keystore-generator/releases) and 
download the latest **annahme-rsa4096.key** file from [ITSG Trust Center](https://www.itsg.de/produkte/trust-center/oeffentliche-zertifikate-und-verzeichnisse/) website. You can also use the key file provided in your certificate request response.

Use the following command to generate the key store. It will prompt you for a password which will be used to secure the key store.

```
java -jar secon-keystore-generator-<version>.jar -k <key-input-filename> -s <key-store-output-filename>
```

## License
MIT
