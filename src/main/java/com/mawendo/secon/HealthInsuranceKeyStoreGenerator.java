package com.mawendo.secon;

import org.tinylog.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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

/**
 * Handle keystore generation for health insurance certificates.
 */
class HealthInsuranceKeyStoreGenerator {
    private final CertificateFactory certificateFactory;
    private final Map<String, Certificate> certificates = new HashMap<>();

    HealthInsuranceKeyStoreGenerator(CertificateFactory certificateFactory) {
        this.certificateFactory = certificateFactory;
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
     * Extract IK from certificate.
     *
     * @param certificate a ITSG TrustCenter certificate
     * @return IK if present
     */
    private Optional<String> getIk(X509Certificate certificate) {
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
     * Parse key form health insurance.
     *
     * @param key string representation of the certificate without BEGIN CERTIFICATE and BEGIN
     *     CERTIFICATE statements
     * @return the certificate
     * @throws CertificateException on parsing errors
     */
    private X509Certificate buildX509Certificate(String key) throws CertificateException {
        String certificateString =
                "-----BEGIN CERTIFICATE-----\n" + key + "\n-----END CERTIFICATE-----\n";
        return (X509Certificate)
                certificateFactory.generateCertificate(
                        new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8)));
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
     * Create new keyStore containing all health insurance certificates.
     *
     * @param storePassword the password used to generate the key store
     */
    KeyStore generateKeyStore(String storePassword) throws SeconKeyStoreGeneratorException {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(null, storePassword.toCharArray());
            for (var entry : certificates.entrySet()) {
                Logger.debug("Add certificate for {} to key store", entry.getKey());
                keystore.setCertificateEntry(entry.getKey(), entry.getValue());
            }
            return keystore;
        } catch (KeyStoreException e) {
            throw new SeconKeyStoreGeneratorException(
                    "Unable to create empty key store instance of type jks: " + e.getMessage(), e);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new SeconKeyStoreGeneratorException("Unable to write key store: " + e.getMessage(), e);
        }
    }
}
