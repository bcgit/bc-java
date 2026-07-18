package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Arrays;

/**
 * Certificate generation tests for the post-quantum KEM public key types (ML-KEM and FrodoKEM).
 * <p>
 * A KEM public key cannot sign, so each leaf certificate carries a KEM subject public key and is
 * issued (signed) by an ML-DSA CA. Per the ML-KEM / FrodoKEM certificate profiles
 * (draft-ietf-lamps-kyber-certificates, draft-smyslov-lamps-frodokem-certificates) a KEM
 * certificate sets keyUsage to keyEncipherment only.
 */
public class PQCCertTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final long ONE_DAY = 24 * 60 * 60 * 1000L;

    private int serialNo = 1;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testMLKEM()
        throws Exception
    {
        CA ca = createMLDSACA();

        String[] names = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
        AlgorithmParameterSpec[] specs = {
            MLKEMParameterSpec.ml_kem_512,
            MLKEMParameterSpec.ml_kem_768,
            MLKEMParameterSpec.ml_kem_1024
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPair kemKp = generateKeyPair("ML-KEM", specs[i]);

            checkKemCertificate(names[i], kemKp, ca);
        }
    }

    public void testFrodoKEM()
        throws Exception
    {
        CA ca = createMLDSACA();

        // a representative spread across parameter set (976/1344), hash (SHAKE/AES) and FrodoKEM/eFrodoKEM
        String[] names = {"frodokem976shake", "frodokem976aes", "frodokem1344shake", "efrodokem976aes"};
        AlgorithmParameterSpec[] specs = {
            FrodoKEMParameterSpec.frodokem976shake,
            FrodoKEMParameterSpec.frodokem976aes,
            FrodoKEMParameterSpec.frodokem1344shake,
            FrodoKEMParameterSpec.efrodokem976aes
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPair kemKp = generateKeyPair("FrodoKEM", specs[i]);

            checkKemCertificate(names[i], kemKp, ca);
        }
    }

    private void checkKemCertificate(String label, KeyPair kemKp, CA ca)
        throws Exception
    {
        X500Principal subject = new X500Principal("CN=" + label + " KEM");

        Date notBefore = new Date(System.currentTimeMillis() - ONE_DAY);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * ONE_DAY);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            ca.certificate, BigInteger.valueOf(serialNo++), notBefore, notAfter, subject, kemKp.getPublic());

        // KEM keys encapsulate a key: keyEncipherment is the only permitted usage.
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment));

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider(BC).build(ca.keyPair.getPrivate());

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(builder.build(signer));

        // signature verifies against the issuing (ML-DSA) CA
        cert.verify(ca.certificate.getPublicKey(), BC);

        assertEquals(label + ": subject mismatch", subject, cert.getSubjectX500Principal());
        assertEquals(label + ": issuer mismatch", ca.certificate.getSubjectX500Principal(), cert.getIssuerX500Principal());

        // the subject public key parsed back out of the certificate matches the generated KEM key
        assertTrue(label + ": public key did not round-trip",
            Arrays.areEqual(kemKp.getPublic().getEncoded(), cert.getPublicKey().getEncoded()));

        boolean[] keyUsage = cert.getKeyUsage();
        assertNotNull(label + ": keyUsage absent", keyUsage);
        assertTrue(label + ": keyEncipherment not set", keyUsage[2]);
        assertFalse(label + ": digitalSignature must not be set on a KEM certificate", keyUsage[0]);
    }

    private CA createMLDSACA()
        throws Exception
    {
        KeyPair caKp = generateKeyPair("ML-DSA", MLDSAParameterSpec.ml_dsa_65);

        X500Principal caName = new X500Principal("CN=BC Test PQC KEM CA");

        Date notBefore = new Date(System.currentTimeMillis() - ONE_DAY);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * ONE_DAY);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            caName, BigInteger.valueOf(serialNo++), notBefore, notAfter, caName, caKp.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").setProvider(BC).build(caKp.getPrivate());

        X509Certificate caCert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(builder.build(signer));

        caCert.verify(caCert.getPublicKey(), BC);

        return new CA(caKp, caCert);
    }

    private KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BC);

        kpg.initialize(spec);

        return kpg.generateKeyPair();
    }

    private static class CA
    {
        final KeyPair keyPair;
        final X509Certificate certificate;

        CA(KeyPair keyPair, X509Certificate certificate)
        {
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(PQCCertTest.class);
    }
}
