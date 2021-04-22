package com.mawendo.secon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.tinylog.Logger;
import org.tinylog.configuration.Configuration;

public class SeconKeyStoreGenerator {
  private static final CertificateFactory CERTIFICATE_FACTORY;
  private static final String DEFAULT_KEY_PATH = "annahme-rsa4096.key";
  private static final String DEFAULT_KEY_STORE_PATH = "healthInsuranceCertificates.p12";

  static {
    try {
      CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new SeconKeyStoreGeneratorException(
          "Unable to create CertificateFactory of type X.509.", e);
    }
  }

  final Map<String, Certificate> certificates = new HashMap<>();

  /** Run generator CLI. */
  public static void main(String[] args) {
    Options options = new Options();
    options.addOption(
        new Option(
            "k", "key-file", true, "path of the key file (default: " + DEFAULT_KEY_PATH + ")"));

    options.addOption(
        new Option(
            "s",
            "key-store-file",
            true,
            "path of key store file (default: " + DEFAULT_KEY_STORE_PATH + ")"));

    options.addOption(new Option(null, "key-store-password", true, "password of key store file"));

    options.addOption(new Option(null, "debug", false, "enable debug logging"));
    options.addOption(new Option(null, "help", false, "print this message"));

    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    formatter.setWidth(120);
    CommandLine cmd = null;

    boolean parseError = false;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      Logger.error(e.getMessage());
      parseError = true;
    }

    if (parseError || cmd.getOptions().length == 0 || cmd.hasOption("help")) {
      formatter.printHelp(SeconKeyStoreGenerator.class.getSimpleName(), options);
      System.exit(1);
    }

    if (cmd.hasOption("debug")) {
      Configuration.set("writer.level", "debug");
    }

    Path keyFilePath =
        Paths.get(cmd.hasOption("key-file") ? cmd.getOptionValue("key-file") : DEFAULT_KEY_PATH);

    Path keyStoreFilePath =
        Paths.get(
            cmd.hasOption("key-store-file")
                ? cmd.getOptionValue("key-store-file")
                : DEFAULT_KEY_STORE_PATH);

    String keyStorePassword =
        cmd.hasOption("key-store-password")
            ? cmd.getOptionValue("key-store-password")
            : new String(System.console().readPassword("Enter password for key store: "));

    SeconKeyStoreGenerator keyStoreCreator = new SeconKeyStoreGenerator();

    try {
      keyStoreCreator.loadHealthInsuranceKeys(keyFilePath);
      keyStoreCreator.writeKeyStore(keyStoreFilePath, keyStorePassword);
    } catch (SeconKeyStoreGeneratorException e) {
      Logger.error(e.getMessage());
      System.exit(1);
    }
  }

  /**
   * Parse key form health insurance.
   *
   * @param key string representation of the certificate without BEGIN CERTIFICATE and BEGIN
   *     CERTIFICATE statements
   * @return the certificate
   * @throws CertificateException on parsing errors
   */
  private static X509Certificate buildX509Certificate(String key) throws CertificateException {
    String certificateString =
        "-----BEGIN CERTIFICATE-----\n" + key + "\n-----END CERTIFICATE-----\n";
    return (X509Certificate)
        CERTIFICATE_FACTORY.generateCertificate(
            new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Extract IK from certificate.
   *
   * @param certificate a ITSG TrustCenter certificate
   * @return IK if present
   */
  private static Optional<String> getIk(X509Certificate certificate) {
    LdapName dn;
    try {
      dn = new LdapName(certificate.getSubjectX500Principal().getName());
    } catch (InvalidNameException e) {
      return Optional.empty();
    }

    return dn.getRdns().stream()
        .filter(r -> r.getType().equalsIgnoreCase("OU") && r.getValue().toString().startsWith("IK"))
        .map(Rdn::getValue)
        .map(Object::toString)
        .findFirst();
  }

  /**
   * Read and parse health insurance certificates.
   *
   * @param keysPath the path to the keys file
   */
  void loadHealthInsuranceKeys(Path keysPath) {
    String[] healthInsuranceKeys = readHealthInsuranceKeys(keysPath);
    int errors = 0;
    for (String key : healthInsuranceKeys) {

      X509Certificate certificate;
      try {
        certificate = buildX509Certificate(key);
      } catch (CertificateException e) {
        Logger.debug("Certificate parsing error: {}", e.getMessage());
        errors++;
        continue;
      }
      Optional<String> ik = getIk(certificate);
      if (ik.isPresent()) {
        certificates.put(ik.get(), certificate);
      } else {
        Logger.debug(
            "No IK in certificate subject: {}", certificate.getSubjectX500Principal().getName());
        errors++;
      }
    }

    if (errors > 0) {
      Logger.warn("Warning: Unable to load " + errors + " certificate(s). ");
    }
  }

  /**
   * Read health insurance keys (e.g. annahme-rsa4096.key).
   *
   * @param keysPath the path of the key file
   * @return array of keys
   */
  private String[] readHealthInsuranceKeys(Path keysPath) {
    if (!Files.exists(keysPath)) {
      throw new SeconKeyStoreGeneratorException("Key file '" + keysPath + "' not found.");
    }
    try {
      return Files.readString(keysPath).split("(?m)^\\s*$");
    } catch (IOException e) {
      throw new SeconKeyStoreGeneratorException("Error reading key file: " + e.getMessage(), e);
    }
  }

  /**
   * Write new keyStore containing all health insurance certificates.
   *
   * @param storePath the path of the key store file
   * @param storePassword the password used to generate the key store
   */
  void writeKeyStore(Path storePath, String storePassword) {
    try (OutputStream outputStream = Files.newOutputStream(storePath)) {
      KeyStore keystore = KeyStore.getInstance("PKCS12");
      keystore.load(null, storePassword.toCharArray());
      for (var entry : certificates.entrySet()) {
        Logger.debug("Add certificate for {} to key store", entry.getKey());
        keystore.setCertificateEntry(entry.getKey(), entry.getValue());
      }
      keystore.store(outputStream, storePassword.toCharArray());
    } catch (KeyStoreException e) {
      throw new SeconKeyStoreGeneratorException(
          "Unable to create empty key store instance of type jks: " + e.getMessage(), e);
    } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new SeconKeyStoreGeneratorException("Unable to write key store: " + e.getMessage(), e);
    }

    Logger.info(
        "Generated key store '" + storePath + "' with " + certificates.size() + " certificates.");
  }
}
