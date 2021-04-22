package com.mawendo.secon;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Handle embedding private keys and keychains in a keystore
 * Will handle files received from ITSG and the private key you generated on application:
 * *.pem (containing only the private key)
 * *.p7c (the certificate chain you received from ITSG)
 */
class PrivateKeyHandler {
  private static final String PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
  private static final String PKCS_1_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";
  private final CertificateFactory certificateFactory;

  PrivateKeyHandler(CertificateFactory certificateFactory) {
    this.certificateFactory = certificateFactory;
  }

  /**
   * Embed a private key and certificate chain in the keystore.
   *
   * @param keystore        the target keystore to write the private key to
   * @param keySourcePath   path to the private key (PKCS1 .pem file with "BEGIN RSA PRIVATE KEY"
   *                        at the top)
   * @param chainSourcePath path to the chain you received from ITSG (.p7c file)
   * @param alias           the alias you wish to give to your private certificate in the keystore
   * @param password        the password to protect your private certificate with
   * @return the keystore containing the private key
   */
  KeyStore embedPrivateKeyInKeyStore(
      KeyStore keystore,
      Path keySourcePath,
      Path chainSourcePath,
      String alias,
      String password
  ) {
    if (!Files.exists(keySourcePath)) {
      throw new SeconKeyStoreGeneratorException("Key file '" + keySourcePath + "' not found.");
    }
    if (!Files.exists(chainSourcePath)) {
      throw new SeconKeyStoreGeneratorException("Chain file '" + chainSourcePath + "' not found.");
    }
    try {
      FileInputStream inputStream = new FileInputStream(chainSourcePath.toFile());
      Certificate[] chain = certificateFactory.generateCertificates(inputStream).stream()
          .map(obj -> (Certificate) obj)
          .toArray(Certificate[]::new);
      PrivateKey privateKey = loadPrivateKey(keySourcePath);
      keystore.setKeyEntry(alias, privateKey, password.toCharArray(), chain);
      return keystore;
    } catch (IOException e) {
      throw new SeconKeyStoreGeneratorException("Failed to open file at: " + keySourcePath);
    } catch (CertificateException e) {
      throw new SeconKeyStoreGeneratorException(
          "Failed create certificate from key file at: " + keySourcePath);
    } catch (KeyStoreException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new SeconKeyStoreGeneratorException("Failed to create keystore");
    }
  }

  // credit to https://github.com/Mastercard/client-encryption-java/blob/master/src/main/java/com/mastercard/developer/utils/EncryptionUtils.java
  // parts of this method is copyright by Mastercard according to their license https://github.com/Mastercard/client-encryption-java/blob/master/LICENSE
  private PrivateKey loadPrivateKey(Path keyPath)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    String keyData = Files.readString(keyPath);
    if (!keyData.contains(PKCS_1_PEM_HEADER)) {
      throw new IllegalArgumentException(
          "Must provide a PKCS1 file (starting with BEGIN RSA PRIVATE KEY)");
    }
    keyData = keyData.replace(PKCS_1_PEM_HEADER, "");
    keyData = keyData.replace(PKCS_1_PEM_FOOTER, "");
    keyData = keyData.replace(System.lineSeparator(), "");
    byte[] decoded = Base64.getDecoder().decode(keyData);
    int pkcs1Length = decoded.length;
    int totalLength = pkcs1Length + 22;
    byte[] manuallyCreatedPkcs8Header = new byte[] {
        0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff),
        0x2, 0x1, 0x0,
        0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1,
        0x5, 0x0,
        0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff)
    };
    byte[] pkcs8bytes = new byte[manuallyCreatedPkcs8Header.length + decoded.length];
    System
        .arraycopy(manuallyCreatedPkcs8Header, 0, pkcs8bytes, 0, manuallyCreatedPkcs8Header.length);
    System.arraycopy(decoded, 0, pkcs8bytes, manuallyCreatedPkcs8Header.length, decoded.length);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8bytes));
  }
}
