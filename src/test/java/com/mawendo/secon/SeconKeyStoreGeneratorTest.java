package com.mawendo.secon;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SeconKeyStoreGeneratorTest {
  @Test
  void writeKeyStore(@TempDir Path tempDir) {
    Path keyStorePath = Paths.get(tempDir.toString(), "test-store.p12");
    String password = "password";
    KeyStore keystore = SeconKeyStoreGenerator.createEmptyKeyStore(password);
    SeconKeyStoreGenerator.writeKeyStore(keystore, keyStorePath, password);
    assertTrue(Files.exists(keyStorePath));
  }

  @Test
  void createEmptyKeyStore() {
    assertDoesNotThrow(() -> SeconKeyStoreGenerator.createEmptyKeyStore("password"));
  }
}
