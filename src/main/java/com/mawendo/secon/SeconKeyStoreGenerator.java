package com.mawendo.secon;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
  static final CertificateFactory CERTIFICATE_FACTORY;
  private static final String DEFAULT_KEY_PATH = "annahme-rsa4096.key";
  private static final String DEFAULT_KEY_STORE_PATH = "certificates.p12";
  private static final String DEFAULT_PRIVATE_KEY_ALIAS = "private";

  static {
    try {
      CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new SeconKeyStoreGeneratorException(
          "Unable to create CertificateFactory of type X.509.", e);
    }
  }

  /**
   * Run generator CLI.
   */
  public static void main(String[] args) {
    Options options = new Options();
    options.addOption(
        new Option(
            "k", "insurance-keys", true,
            "path of the insurance keys file (default: " + DEFAULT_KEY_PATH + ")"));

    options.addOption(
        new Option(
            "s",
            "key-store-file",
            true,
            "path of output .p12 key store file (default: " + DEFAULT_KEY_STORE_PATH + ")"));

    options.addOption(
        new Option(
            "p",
            "private-key",
            true,
            "(optional) path of your private key (PKCS1 .pem file beginning with"
                + " '--BEGIN RSA PRIVATE KEY--')"));

    options.addOption(
        new Option(
            "c",
            "chain",
            true,
            "(optional) path of your certificate chain (.p7c file received from ITSG)"));

    options.addOption(new Option("a", "alias", true,
        "the alias of your private key in the keystore (default: "
            + DEFAULT_PRIVATE_KEY_ALIAS
            + ")"));
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

    if (parseError || cmd.hasOption("help")) {
      formatter.printHelp(SeconKeyStoreGenerator.class.getSimpleName(), options);
      System.exit(1);
    }

    boolean shouldEmbedPrivateKey = false;
    if (cmd.hasOption("private-key") || cmd.hasOption("chain")) {
      if (!cmd.hasOption("chain") || !cmd.hasOption("private-key")) {
        Logger.error(
            "To embed your private key in the keystore you must provide both a PEM private key"
                + " (--private-key) and a P7C certificate chain (--chain)"
        );
        formatter.printHelp(SeconKeyStoreGenerator.class.getSimpleName(), options);
        System.exit(1);
      }
      shouldEmbedPrivateKey = true;
    }

    if (cmd.hasOption("debug")) {
      Configuration.set("writer.level", "debug");
    }

    Path keyFilePath =
        Paths.get(cmd.hasOption("insurance-keys") ? cmd.getOptionValue("insurance-keys") :
            DEFAULT_KEY_PATH);

    Path keyStoreFilePath =
        Paths.get(
            cmd.hasOption("key-store-file")
                ? cmd.getOptionValue("key-store-file")
                : DEFAULT_KEY_STORE_PATH);

    String keyStorePassword =
        cmd.hasOption("key-store-password")
            ? cmd.getOptionValue("key-store-password")
            : new String(System.console().readPassword("Enter password for key store: "));

    String privateKeyAlias =
        cmd.hasOption("alias")
            ? cmd.getOptionValue("alias")
            : DEFAULT_PRIVATE_KEY_ALIAS;

    try {
      KeyStore keystore = createEmptyKeyStore(keyStorePassword);
      HealthInsuranceKeyHandler healthInsuranceKeyHandler =
          new HealthInsuranceKeyHandler(CERTIFICATE_FACTORY);
      healthInsuranceKeyHandler.embedCertificatesInKeyStore(keystore, keyFilePath);
      Logger.debug(
          "Successfully embedded health insurance certificates in keystore");

      if (shouldEmbedPrivateKey) {
        Path privateKeyPath = Paths.get(cmd.getOptionValue("private-key"));
        Path chain = Paths.get(cmd.getOptionValue("chain"));
        PrivateKeyHandler generator = new PrivateKeyHandler(CERTIFICATE_FACTORY);
        generator.embedPrivateKeyInKeyStore(keystore, privateKeyPath, chain, privateKeyAlias,
            keyStorePassword);
        Logger.debug(
            "Successfully embedded private key in keystore with alias '" + privateKeyAlias + "'");
      }
      writeKeyStore(keystore, keyStoreFilePath, keyStorePassword);
    } catch (SeconKeyStoreGeneratorException e) {
      Logger.error(e.getMessage());
      System.exit(1);
    }
  }

  /**
   * Create an empty key store.
   * @param password
   * @return
   */
  static KeyStore createEmptyKeyStore(String password) {
    try {
      KeyStore keystore = KeyStore.getInstance("PKCS12");
      keystore.load(null, password.toCharArray());
      return keystore;
    } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new SeconKeyStoreGeneratorException("Unable to create empty key store instance: "
          + e.getMessage(), e);
    }
  }

  /**
   * Write new keyStore to disk.
   *
   * @param keystore      the keystore to write
   * @param storePath     the path of the key store file
   * @param storePassword the password used to generate the key store
   */
  static void writeKeyStore(KeyStore keystore, Path storePath, String storePassword) {
    try (OutputStream outputStream = Files.newOutputStream(storePath)) {
      keystore.store(outputStream, storePassword.toCharArray());
    } catch (KeyStoreException e) {
      throw new SeconKeyStoreGeneratorException(
          "Unable to create empty key store instance of type jks: " + e.getMessage(), e);
    } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
      throw new SeconKeyStoreGeneratorException("Unable to write key store: " + e.getMessage(), e);
    }

    Logger.info(
        "Generated key store '" + storePath + "'");
  }
}
