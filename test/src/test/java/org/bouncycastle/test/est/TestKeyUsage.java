package org.bouncycastle.test.est;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;


public class TestKeyUsage
    extends SimpleTest
{
    private static int[] keyUsage = new int[]{
        0,
        KeyUsage.digitalSignature,
        KeyUsage.nonRepudiation,
        KeyUsage.keyEncipherment,
        KeyUsage.dataEncipherment,
        KeyUsage.keyAgreement,
        KeyUsage.keyCertSign,
        KeyUsage.cRLSign,
        KeyUsage.encipherOnly,
        KeyUsage.decipherOnly
    };

    private static KeyPurposeId[] keyPurposes = new KeyPurposeId[]{
        null,
        KeyPurposeId.id_kp_serverAuth,
        KeyPurposeId.id_kp_msSGC,
        KeyPurposeId.id_kp_nsSGC,
        KeyPurposeId.id_kp_clientAuth,
    };

    public String getName()
    {
        return "TestKeyUsage";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestKeyUsage.class);
    }

    @Test
    public void testWith_0()
        throws Exception
    {

        //
        // With no key usage and no extended key usage.
        //

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();

        boolean result[] = new boolean[keyUsage.length * keyPurposes.length];


        X509Certificate cert = makeCertificate(originalKeyPair, null, null);

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_1()
        throws Exception
    {

        // With digitalSignature, and no extended key usage


        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.digitalSignature));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_2()
        throws Exception
    {

        // With keyEncipherment and no extended key usage

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyEncipherment));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_3()
        throws Exception
    {

        // With digitalSignature and keyEncipherment and no extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

    @Test
    public void testCertUsage_4()
        throws Exception
    {

        // With digitalSignature, keyEncipherment amd keyAgreement no extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test(expected = CertificateException.class)
    public void testCertUsage_5()
        throws Exception
    {

        // With keyAgreement no extended key usage -- must fail.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        X509Certificate cert = makeCertificate(originalKeyPair, null, new KeyUsage(KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_6()
        throws Exception
    {

        // Valid key usage with serverAuth extended key usage

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_serverAuth);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_7()
        throws Exception
    {

        // Valid key usage with msSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_msSGC);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

    @Test
    public void testCertUsage_8()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_nsSGC);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }

    @Test
    public void testCertUsage_9()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_serverAuth);
        purpose.add(KeyPurposeId.id_kp_msSGC);
        purpose.add(KeyPurposeId.id_kp_nsSGC);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test
    public void testCertUsage_10()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();
        purpose.add(KeyPurposeId.id_kp_serverAuth);
        purpose.add(KeyPurposeId.id_kp_msSGC);
        purpose.add(KeyPurposeId.id_kp_nsSGC);
        purpose.add(KeyPurposeId.id_kp_clientAuth);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    @Test(expected = CertificateException.class)
    public void testCertUsage_11()
        throws Exception
    {

        // Valid key usage with nsSGC extended key usage.

        ESTTestUtils.ensureProvider();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();


        ASN1EncodableVector purpose = new ASN1EncodableVector();

        purpose.add(KeyPurposeId.id_kp_clientAuth);

        X509Certificate cert = makeCertificate(
            originalKeyPair,
            purpose,
            new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement));

        // Should not reject.
        JcaJceUtils.validateServerCertUsage(cert);

    }


    private X509Certificate makeCertificate(KeyPair originalKeyPair, ASN1EncodableVector purposes, KeyUsage keyUsage)
        throws Exception
    {
        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.CN, "Bunyip Bluegum");
        builder.addRDN(BCStyle.O, "Pudding Protectors");
        builder.addRDN(BCStyle.L, "Victoria");

        X500Name name = builder.build();

        X509Certificate clientTLSCert = ESTTestUtils.createASignedCert("SHA256WITHECDSA",
            name,
            SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
            name,
            originalKeyPair.getPrivate(),
            1, purposes, keyUsage
        );

        return clientTLSCert;
    }


}
