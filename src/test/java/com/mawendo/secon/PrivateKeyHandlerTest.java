package com.mawendo.secon;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class PrivateKeyHandlerTest {
  @Test
  void embedPrivateKeyInKeyStore() throws KeyStoreException {
    PrivateKeyHandler handler = new PrivateKeyHandler(SeconKeyStoreGenerator.CERTIFICATE_FACTORY);
    String password = "test";
    KeyStore keystore = SeconKeyStoreGenerator.createEmptyKeyStore(password);
    Path keySourcePath = Paths.get("src", "test", "resources", "private-key.pem");
    Path chainSourcePath = Paths.get("src", "test", "resources", "chain.p7c");
    String alias = "private";
    handler.embedPrivateKeyInKeyStore(
        keystore,
        keySourcePath,
        chainSourcePath,
        alias,
        password
    );
    X509Certificate certificate = (X509Certificate) keystore.getCertificateChain(alias)[0];
    assertTrue(keystore.containsAlias(alias));
    assertTrue(
        certificate.getSubjectX500Principal().getName().contains("O=Secon Keystore Generator"));

  }
}
