package com.mawendo.secon;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SeconKeyStoreGeneratorTest {

  @Test
  void loadHealthInsuranceKeys() {
    SeconKeyStoreGenerator generator = new SeconKeyStoreGenerator();

    generator.loadHealthInsuranceKeys(Paths.get("src", "test", "resources", "valid-rsa4096.key"));

    assertEquals(3, generator.certificates.size());
  }

  @Test
  void writeKeyStore(@TempDir Path tempDir) throws Exception {
    SeconKeyStoreGenerator generator = new SeconKeyStoreGenerator();
    generator.loadHealthInsuranceKeys(Paths.get("src", "test", "resources", "valid-rsa4096.key"));
    Path keyStorePath = Paths.get(tempDir.toString(), "test-store.p12");

    generator.writeKeyStore(keyStorePath, "test-pw");

    assertTrue(Files.exists(keyStorePath));
    KeyStore keyStore = KeyStore.getInstance(keyStorePath.toFile(), "test-pw".toCharArray());
    assertEquals(3, generator.certificates.size());
    for (String ik : generator.certificates.keySet()) {
      assertTrue(keyStore.containsAlias(ik));
    }
  }
}
