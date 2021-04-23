package com.mawendo.secon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HealthInsuranceKeyHandlerTest {

  @Test
  void embedCertificatesInKeyStore(@TempDir Path tempDir) throws Exception {

    String password = "test";
    HealthInsuranceKeyHandler generator =
        new HealthInsuranceKeyHandler(SeconKeyStoreGenerator.CERTIFICATE_FACTORY);
    KeyStore keystore = SeconKeyStoreGenerator.createEmptyKeyStore(password);
    generator.embedCertificatesInKeyStore(keystore, Paths.get("src", "test", "resources", "valid-rsa4096.key"));
    Path keyStorePath = Paths.get(tempDir.toString(), "test-store.p12");

    SeconKeyStoreGenerator.writeKeyStore(keystore, keyStorePath, password);

    assertTrue(Files.exists(keyStorePath));
    KeyStore keyStore = KeyStore.getInstance(keyStorePath.toFile(), password.toCharArray());
    assertEquals(3, generator.certificates.size());
    for (String ik : generator.certificates.keySet()) {
      assertTrue(keyStore.containsAlias(ik));
    }
  }
}
