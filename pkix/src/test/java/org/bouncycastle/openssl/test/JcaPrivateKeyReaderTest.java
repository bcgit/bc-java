package org.bouncycastle.openssl.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPKIXIdentityBuilder;
import org.bouncycastle.openssl.jcajce.JcaPrivateKeyReader;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.JcaPKIXIdentity;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Round-trips an RSA key through every encoding {@link JcaPrivateKeyReader} claims to read:
 * PKCS#1 (PEM and DER), PKCS#8 (PEM and DER), password-protected traditional, and encrypted PKCS#8.
 */
public class JcaPrivateKeyReaderTest
    extends SimpleTest
{
    private static final char[] PASSWORD = "secret".toCharArray();

    public String getName()
    {
        return "JcaPrivateKeyReaderTest";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(2048);
        KeyPair pair = kpGen.generateKeyPair();
        PrivateKey privKey = pair.getPrivate();

        doPKCS8PEM(privKey);
        doPKCS8DER(privKey);
        doPKCS1PEM(privKey);
        doPKCS1DER(privKey);
        doEncryptedTraditionalPEM(privKey);
        doEncryptedPKCS8PEM(privKey);
        doEncryptedPKCS8DER(privKey);

        doStreamAndByteEntryPoints(privKey);
        doFailureCases(privKey);
        doMalformedDERCases();
        doIdentityBuilderEncryptedKey(pair);
    }

    private void doIdentityBuilderEncryptedKey(KeyPair pair)
        throws Exception
    {
        X509Certificate cert = selfSignedCert(pair);

        // Encrypted traditional PEM key + PEM cert, decrypted via the builder's new setPassword().
        String keyPem = writePEM(new JcaMiscPEMGenerator(pair.getPrivate(),
            new JcePEMEncryptorBuilder("AES-256-CBC").setProvider("BC").build(PASSWORD)));
        String certPem = writePEM(new JcaMiscPEMGenerator(cert));

        JcaPKIXIdentity identity = new JcaPKIXIdentityBuilder()
            .setProvider("BC")
            .setPassword(PASSWORD)
            .build(new ByteArrayInputStream(keyPem.getBytes()), new ByteArrayInputStream(certPem.getBytes()));

        isTrue("identity key mismatch",
            Arrays.areEqual(pair.getPrivate().getEncoded(), identity.getPrivateKey().getEncoded()));
        isTrue("identity cert missing", identity.getX509Certificate() != null);
        areEqual(cert.getEncoded(), identity.getX509Certificate().getEncoded());
    }

    private static X509Certificate selfSignedCert(KeyPair pair)
        throws Exception
    {
        X500Name name = new X500Name("CN=JcaPrivateKeyReaderTest");
        Date notBefore = new Date(System.currentTimeMillis() - 5000L);
        Date notAfter = new Date(System.currentTimeMillis() + 24L * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(1), notBefore, notAfter, name, pair.getPublic());

        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(certBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate())));
    }

    private void doPKCS8PEM(PrivateKey privKey)
        throws Exception
    {
        String pem = writePEM(new JcaMiscPEMGenerator(privKey)); // BEGIN PRIVATE KEY
        check("PKCS#8 PEM", privKey, new JcaPrivateKeyReader().setProvider("BC").readKey(pem.getBytes()));
    }

    private void doPKCS8DER(PrivateKey privKey)
        throws Exception
    {
        byte[] der = privKey.getEncoded(); // PKCS#8 PrivateKeyInfo DER
        check("PKCS#8 DER", privKey, new JcaPrivateKeyReader().setProvider("BC").readKey(der));
    }

    private void doPKCS1PEM(PrivateKey privKey)
        throws Exception
    {
        // A bare RSAPrivateKey wrapped as "BEGIN RSA PRIVATE KEY".
        PemObject pemObj = new PemObject("RSA PRIVATE KEY", pkcs1DER(privKey));
        String pem = writePem(pemObj);
        check("PKCS#1 PEM", privKey, new JcaPrivateKeyReader().setProvider("BC").readKey(pem.getBytes()));
    }

    private void doPKCS1DER(PrivateKey privKey)
        throws Exception
    {
        check("PKCS#1 DER", privKey, new JcaPrivateKeyReader().setProvider("BC").readKey(pkcs1DER(privKey)));
    }

    private void doEncryptedTraditionalPEM(PrivateKey privKey)
        throws Exception
    {
        String pem = writePEM(new JcaMiscPEMGenerator(privKey,
            new JcePEMEncryptorBuilder("AES-256-CBC").setProvider("BC").build(PASSWORD)));

        check("encrypted traditional PEM", privKey,
            new JcaPrivateKeyReader(PASSWORD).setProvider("BC").readKey(pem.getBytes()));
    }

    private void doEncryptedPKCS8PEM(PrivateKey privKey)
        throws Exception
    {
        String pem = writePEM(new JcaPKCS8Generator(privKey, encryptedPKCS8()));
        check("encrypted PKCS#8 PEM", privKey,
            new JcaPrivateKeyReader(PASSWORD).setProvider("BC").readKey(pem.getBytes()));
    }

    private void doEncryptedPKCS8DER(PrivateKey privKey)
        throws Exception
    {
        // JcaPKCS8Generator wraps the EncryptedPrivateKeyInfo in a PEM object; pull the DER body out.
        PemObject obj = new JcaPKCS8Generator(privKey, encryptedPKCS8()).generate();
        check("encrypted PKCS#8 DER", privKey,
            new JcaPrivateKeyReader(PASSWORD).setProvider("BC").readKey(obj.getContent()));
    }

    private void doStreamAndByteEntryPoints(PrivateKey privKey)
        throws Exception
    {
        byte[] der = privKey.getEncoded();

        check("InputStream entry point", privKey,
            new JcaPrivateKeyReader().setProvider("BC").readKey(new ByteArrayInputStream(der)));
    }

    private void doFailureCases(PrivateKey privKey)
        throws Exception
    {
        // Encrypted key, no password.
        String pem = writePEM(new JcaPKCS8Generator(privKey, encryptedPKCS8()));
        try
        {
            new JcaPrivateKeyReader().setProvider("BC").readKey(pem.getBytes());
            fail("no exception on encrypted key without password");
        }
        catch (PEMException e)
        {
            isTrue("wrong message: " + e.getMessage(),
                e.getMessage().equals("encrypted private key but no password supplied"));
        }

        // Empty input.
        try
        {
            new JcaPrivateKeyReader().readKey(new byte[0]);
            fail("no exception on empty input");
        }
        catch (PEMException e)
        {
            isTrue("wrong message: " + e.getMessage(), e.getMessage().equals("no key data found"));
        }

        // DER that is not a SEQUENCE (an INTEGER).
        try
        {
            new JcaPrivateKeyReader().readKey(new byte[]{0x02, 0x01, 0x00});
            fail("no exception on non-SEQUENCE DER");
        }
        catch (PEMException e)
        {
            // expected - PEM parse of 0x02... yields no PEM object, or a DER non-SEQUENCE.
        }
    }

    private void doMalformedDERCases()
        throws Exception
    {
        // DER that passes readDER's outer-shape guards (SEQUENCE, size >= 2, first element
        // INTEGER) but whose inner content is structurally wrong, so the inner getInstance
        // throws an unchecked exception. readKey() must surface that as a PEMException, never
        // let it escape the throws IOException contract (finding #34).

        // { INTEGER 0, SEQUENCE { INTEGER 1 } } routes to the PrivateKeyInfo.getInstance
        // branch (second element is a SEQUENCE) -> IllegalArgumentException.
        checkMalformedDER(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), new DERSequence(new ASN1Integer(1)) }).getEncoded(),
            "PrivateKeyInfo path");

        // { INTEGER 0, INTEGER 1, INTEGER 2 } routes to the RSAPrivateKey.getInstance branch
        // (second element is not a SEQUENCE) -> NoSuchElementException.
        checkMalformedDER(new DERSequence(new ASN1Encodable[]{
            new ASN1Integer(0), new ASN1Integer(1), new ASN1Integer(2) }).getEncoded(),
            "RSAPrivateKey path");
    }

    private void checkMalformedDER(byte[] der, String label)
        throws Exception
    {
        try
        {
            new JcaPrivateKeyReader().setProvider("BC").readKey(der);
            fail("malformed DER not rejected: " + label);
        }
        catch (PEMException e)
        {
            // expected - the throws IOException contract is preserved
        }
        catch (RuntimeException e)
        {
            fail(label + " leaked " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    private void check(String label, PrivateKey expected, PrivateKey actual)
    {
        isTrue(label + ": null key", actual != null);
        isTrue(label + ": key mismatch", Arrays.areEqual(expected.getEncoded(), actual.getEncoded()));
    }

    private OutputEncryptor encryptedPKCS8()
        throws Exception
    {
        return new JceOpenSSLPKCS8EncryptorBuilder(JcaPKCS8Generator.AES_256_CBC)
            .setProvider("BC")
            .setPassword(PASSWORD)
            .build();
    }

    private static byte[] pkcs1DER(PrivateKey privKey)
        throws IOException
    {
        // PKCS#8 -> the inner RSAPrivateKey -> its DER is exactly the PKCS#1 body.
        return PrivateKeyInfo.getInstance(privKey.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded();
    }

    private static String writePEM(PemObjectGenerator pemGenerator)
        throws IOException
    {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw);
        pemWriter.writeObject(pemGenerator);
        pemWriter.close();
        return sw.toString();
    }

    private static String writePem(PemObject pemObject)
        throws IOException
    {
        StringWriter sw = new StringWriter();
        PemWriter pemWriter = new PemWriter(sw);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return sw.toString();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new JcaPrivateKeyReaderTest());
    }
}
