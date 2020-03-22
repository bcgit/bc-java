package org.bouncycastle.openssl.test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.CertificateTrustBlock;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.X509TrustedCertificateBlock;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * basic class for reading test.pem - the password is "secret"
 */
public class ParserTest
    extends SimpleTest
{
    public String getName()
    {
        return "PEMParserTest";
    }


    private PEMParser openPEMResource(
        String          fileName)
    {
        InputStream res = this.getClass().getResourceAsStream(fileName);
        Reader fRd = new BufferedReader(new InputStreamReader(res));
        return new PEMParser(fRd);
    }

    public void performTest()
        throws Exception
    {
        PEMParser       pemRd = openPEMResource("test.pem");
        Object          o;
        PEMKeyPair      pemPair;
        KeyPair         pair;

        while ((o = pemRd.readObject()) != null)
        {
            if (o instanceof KeyPair)
            {
                //pair = (KeyPair)o;

                //System.out.println(pair.getPublic());
                //System.out.println(pair.getPrivate());
            }
            else
            {
                //System.out.println(o.toString());
            }
        }

        // test bogus lines before begin are ignored.
        pemRd = openPEMResource("extratest.pem");

        while ((o = pemRd.readObject()) != null)
        {
            if (!(o instanceof X509CertificateHolder))
            {
                fail("wrong object found");
            }
        }

        //
        // pkcs 7 data
        //
        pemRd = openPEMResource("pkcs7.pem");
        ContentInfo d = (ContentInfo)pemRd.readObject();

        if (!d.getContentType().equals(CMSObjectIdentifiers.envelopedData))
        {
            fail("failed envelopedData check");
        }

        //
        // ECKey
        //
        pemRd = openPEMResource("eckey.pem");
        ASN1ObjectIdentifier ecOID = (ASN1ObjectIdentifier)pemRd.readObject();
        X9ECParameters ecSpec = ECNamedCurveTable.getByOID(ecOID);

        if (ecSpec == null)
        {
            fail("ecSpec not found for named curve");
        }

        pemPair = (PEMKeyPair)pemRd.readObject();

        pair = new JcaPEMKeyConverter().setProvider("BC").getKeyPair(pemPair);

        Signature sgr = Signature.getInstance("ECDSA", "BC");

        sgr.initSign(pair.getPrivate());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(pair.getPublic());

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("EC verification failed");
        }

        if (!pair.getPublic().getAlgorithm().equals("ECDSA"))
        {
            fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
        }

        if (!pair.getPrivate().getAlgorithm().equals("ECDSA"))
        {
            fail("wrong algorithm name on private");
        }

        //
        // ECKey -- explicit parameters
        //
        pemRd = openPEMResource("ecexpparam.pem");
        ecSpec = (X9ECParameters)pemRd.readObject();

        pemPair = (PEMKeyPair)pemRd.readObject();

        pair = new JcaPEMKeyConverter().setProvider("BC").getKeyPair(pemPair);

        sgr = Signature.getInstance("ECDSA", "BC");

        sgr.initSign(pair.getPrivate());

        message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.update(message);

        sigBytes = sgr.sign();

        sgr.initVerify(pair.getPublic());

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("EC verification failed");
        }

        if (!pair.getPublic().getAlgorithm().equals("ECDSA"))
        {
            fail("wrong algorithm name on public got: " + pair.getPublic().getAlgorithm());
        }

        if (!pair.getPrivate().getAlgorithm().equals("ECDSA"))
        {
            fail("wrong algorithm name on private");
        }

        //
        // writer/parser test
        //
        KeyPairGenerator      kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        pair = kpGen.generateKeyPair();

        keyPairTest("RSA", pair);

        kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        kpGen.initialize(512, new SecureRandom());
        pair = kpGen.generateKeyPair();

        keyPairTest("DSA", pair);

        //
        // PKCS7
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

        pWrt.writeObject(d);

        pWrt.close();

        pemRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));
        d = (ContentInfo)pemRd.readObject();

        if (!d.getContentType().equals(CMSObjectIdentifiers.envelopedData))
        {
            fail("failed envelopedData recode check");
        }


        // OpenSSL test cases (as embedded resources)
        doOpenSslDsaTest("unencrypted");
        doOpenSslRsaTest("unencrypted");

        doOpenSslTests("aes128");
        doOpenSslTests("aes192");
        doOpenSslTests("aes256");
        doOpenSslTests("blowfish");
        doOpenSslTests("des1");
        doOpenSslTests("des2");
        doOpenSslTests("des3");
        doOpenSslTests("rc2_128");

        doOpenSslDsaTest("rc2_40_cbc");
        doOpenSslRsaTest("rc2_40_cbc");
        doOpenSslDsaTest("rc2_64_cbc");
        doOpenSslRsaTest("rc2_64_cbc");

        doDudPasswordTest("7fd98", 0, "corrupted stream - out of bounds length found: 599005160 >= 447");
        doDudPasswordTest("ef677", 1, "corrupted stream - out of bounds length found: 2087569732 >= 447");
        doDudPasswordTest("800ce", 2, "unknown tag 26 encountered");
        doDudPasswordTest("b6cd8", 3, "DEF length 81 object truncated by 56");
        doDudPasswordTest("28ce09", 4, "DEF length 110 object truncated by 28");
        doDudPasswordTest("2ac3b9", 5, "DER length more than 4 bytes: 11");
        doDudPasswordTest("2cba96", 6, "DEF length 100 object truncated by 35");
        doDudPasswordTest("2e3354", 7, "DEF length 42 object truncated by 9");
        doDudPasswordTest("2f4142", 8, "DER length more than 4 bytes: 14");
        doDudPasswordTest("2fe9bb", 9, "DER length more than 4 bytes: 65");
        doDudPasswordTest("3ee7a8", 10, "DER length more than 4 bytes: 57");
        doDudPasswordTest("41af75", 11, "unknown tag 16 encountered");
        doDudPasswordTest("1704a5", 12, "corrupted stream detected");
        doDudPasswordTest("1c5822", 13, "Extra data detected in stream");
        doDudPasswordTest("5a3d16", 14, "corrupted stream detected");
        doDudPasswordTest("8d0c97", 15, "corrupted stream detected");
        doDudPasswordTest("bc0daf", 16, "corrupted stream detected");
        doDudPasswordTest("aaf9c4d",17, "corrupted stream - out of bounds length found: 1580418590 >= 447");

        doNoPasswordTest();
        doNoECPublicKeyTest();

        // encrypted private key test
        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build("password".toCharArray());
        pemRd = openPEMResource("enckey.pem");

        PKCS8EncryptedPrivateKeyInfo encPrivKeyInfo = (PKCS8EncryptedPrivateKeyInfo)pemRd.readObject();
        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider("BC");

        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey)converter.getPrivateKey(encPrivKeyInfo.decryptPrivateKeyInfo(pkcs8Prov));

        if (!privKey.getPublicExponent().equals(new BigInteger("10001", 16)))
        {
            fail("decryption of private key data check failed");
        }

        // general PKCS8 test

        pemRd = openPEMResource("pkcs8test.pem");

        Object privInfo;

        while ((privInfo = pemRd.readObject()) != null)
        {
            if (privInfo instanceof PrivateKeyInfo)
            {
                privKey = (RSAPrivateCrtKey)converter.getPrivateKey(PrivateKeyInfo.getInstance(privInfo));
            }
            else
            {
                privKey = (RSAPrivateCrtKey)converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo)privInfo).decryptPrivateKeyInfo(pkcs8Prov));
            }
            if (!privKey.getPublicExponent().equals(new BigInteger("10001", 16)))
            {
                fail("decryption of private key data check failed");
            }
        }

        pemRd = openPEMResource("trusted_cert.pem");

        X509TrustedCertificateBlock trusted = (X509TrustedCertificateBlock)pemRd.readObject();

        checkTrustedCert(trusted);

        StringWriter stringWriter = new StringWriter();

        pWrt = new JcaPEMWriter(stringWriter);

        pWrt.writeObject(trusted);

        pWrt.close();

        pemRd = new PEMParser(new StringReader(stringWriter.toString()));

        trusted = (X509TrustedCertificateBlock)pemRd.readObject();

        checkTrustedCert(trusted);

        //
        // EdDSAKey
        //
        byte[] msg = Strings.toByteArray("Hello, world!");

        pemRd = openPEMResource("eddsapriv.pem");

        PrivateKeyInfo edPrivInfo = (PrivateKeyInfo)pemRd.readObject();

        EdDSAPrivateKey edPrivKey = (EdDSAPrivateKey)new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(edPrivInfo);

        EdDSAPublicKey edPubKey = edPrivKey.getPublicKey();

        Signature edSig = Signature.getInstance(edPrivKey.getAlgorithm(), "BC");

        edSig.initSign(edPrivKey);

        edSig.update(msg);

        byte[] s = edSig.sign();

        edSig.initVerify(edPubKey);

        edSig.update(msg);

        isTrue(edSig.verify(s));

        doOpenSslGost2012Test();
    }

    private void checkTrustedCert(X509TrustedCertificateBlock trusted)
    {
        CertificateTrustBlock trustBlock = trusted.getTrustBlock();

        if (!"Fred".equals(trustBlock.getAlias()))
        {
            fail("alias not found");
        }

        if (trustBlock.getUses().size() != 3)
        {
            fail("key purpose usages wrong size");
        }
        if (!trustBlock.getUses().contains(KeyPurposeId.id_kp_OCSPSigning.toOID()))
        {
            fail("key purpose use not found");
        }

        if (trustBlock.getProhibitions().size() != 1)
        {
            fail("key purpose prohibitions wrong size");
        }
        if (!trustBlock.getProhibitions().contains(KeyPurposeId.id_kp_clientAuth.toOID()))
        {
            fail("key purpose prohibition not found");
        }
    }

    private void keyPairTest(
        String   name,
        KeyPair pair)
        throws IOException
    {
        PEMParser pemRd;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        JcaPEMWriter             pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

        pWrt.writeObject(pair.getPublic());

        pWrt.close();

        pemRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

        SubjectPublicKeyInfo pub = SubjectPublicKeyInfo.getInstance(pemRd.readObject());
        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider("BC");

        PublicKey k = converter.getPublicKey(pub);

        if (!k.equals(pair.getPublic()))
        {
            fail("Failed public key read: " + name);
        }

        bOut = new ByteArrayOutputStream();
        pWrt = new JcaPEMWriter(new OutputStreamWriter(bOut));

        pWrt.writeObject(pair.getPrivate());

        pWrt.close();

        pemRd = new PEMParser(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));

        KeyPair kPair = converter.getKeyPair((PEMKeyPair)pemRd.readObject());
        if (!kPair.getPrivate().equals(pair.getPrivate()))
        {
            fail("Failed private key read: " + name);
        }

        if (!kPair.getPublic().equals(pair.getPublic()))
        {
            fail("Failed private key public read: " + name);
        }
    }

    private void doOpenSslTests(
        String baseName)
        throws IOException
    {
        doOpenSslDsaModesTest(baseName);
        doOpenSslRsaModesTest(baseName);
    }

    private void doOpenSslDsaModesTest(
        String baseName)
        throws IOException
    {
        doOpenSslDsaTest(baseName + "_cbc");
        doOpenSslDsaTest(baseName + "_cfb");
        doOpenSslDsaTest(baseName + "_ecb");
        doOpenSslDsaTest(baseName + "_ofb");
    }

    private void doOpenSslRsaModesTest(
        String baseName)
        throws IOException
    {
        doOpenSslRsaTest(baseName + "_cbc");
        doOpenSslRsaTest(baseName + "_cfb");
        doOpenSslRsaTest(baseName + "_ecb");
        doOpenSslRsaTest(baseName + "_ofb");
    }

    private void doOpenSslDsaTest(
        String name)
        throws IOException
    {
        String fileName = "dsa/openssl_dsa_" + name + ".pem";

        doOpenSslTestFile(fileName, DSAPrivateKey.class);
    }

    private void doOpenSslRsaTest(
        String name)
        throws IOException
    {
        String fileName = "rsa/openssl_rsa_" + name + ".pem";

        doOpenSslTestFile(fileName, RSAPrivateKey.class);
    }

    private void doOpenSslTestFile(
        String  fileName,
        Class   expectedPrivKeyClass)
        throws IOException
    {
        keyDecryptTest(fileName, expectedPrivKeyClass, new JcePEMDecryptorProviderBuilder().setProvider("BC").build("changeit".toCharArray()));
        keyDecryptTest(fileName, expectedPrivKeyClass, new BcPEMDecryptorProvider("changeit".toCharArray()));
    }

    private void doOpenSslGost2012Test()
        throws Exception
    {
        try
        {
            KeyFactory.getInstance("ECGOST3410-2012", "BC"); // check for algorithm
        }
        catch (Exception e)
        {
            return;
        }

        String fileName = "gost2012_priv.pem";

        PEMParser pr = openPEMResource("data/" + fileName);
        PKCS8EncryptedPrivateKeyInfo pInfo = (PKCS8EncryptedPrivateKeyInfo)pr.readObject();

        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build("test".toCharArray());

        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", "BC");

        PrivateKey privKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(pInfo.decryptPrivateKeyInfo(pkcs8Prov).getEncoded()));

        pr = openPEMResource("data/gost2012_cert.pem");
        X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(
            new ByteArrayInputStream(((X509CertificateHolder)pr.readObject()).getEncoded()));

        cert.verify(cert.getPublicKey());
    }

    private void keyDecryptTest(String fileName, Class expectedPrivKeyClass, PEMDecryptorProvider decProv)
        throws IOException
    {
        PEMParser pr = openPEMResource("data/" + fileName);
        Object o = pr.readObject();

        if (o == null || !((o instanceof PEMKeyPair) || (o instanceof PEMEncryptedKeyPair)))
        {
            fail("Didn't find OpenSSL key");
        }

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp = (o instanceof PEMEncryptedKeyPair) ?
            converter.getKeyPair(((PEMEncryptedKeyPair)o).decryptKeyPair(decProv)) : converter.getKeyPair((PEMKeyPair)o);

        PrivateKey privKey = kp.getPrivate();

        if (!expectedPrivKeyClass.isInstance(privKey))
        {
            fail("Returned key not of correct type");
        }
    }

    private void doDudPasswordTest(String password, int index, String message)
    {
        // illegal state exception check - in this case the wrong password will
        // cause an underlying class cast exception.
        try
        {
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());

            PEMParser pemRd = openPEMResource("test.pem");
            Object o;

            while ((o = pemRd.readObject()) != null)
            {
                if (o instanceof PEMEncryptedKeyPair)
                {
                    ((PEMEncryptedKeyPair)o).decryptKeyPair(decProv);
                }
            }

            fail("issue not detected: " + index);
        }
        catch (IOException e)
        {
            if (e.getCause() != null && !e.getCause().getMessage().endsWith(message))
            {
               fail("issue " + index + " exception thrown, but wrong message");
            }
            else if (e.getCause() == null && !e.getMessage().equals(message))
            {
               fail("issue " + index + " exception thrown, but wrong message");
            }
        }
    }

    private void doNoPasswordTest()
        throws IOException
    {
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().setProvider("BC").build("".toCharArray());

        PEMParser pemRd = openPEMResource("smimenopw.pem");
        Object o;
        PrivateKeyInfo key = null;

        while ((o = pemRd.readObject()) != null)
        {
             key = (PrivateKeyInfo)o;
        }

        if (key == null)
        {
            fail("private key not detected");
        }
    }

    private void doNoECPublicKeyTest()
        throws Exception
    {
        // EC private key without the public key defined. Note: this encoding is actually invalid.
        String ecSample =
                    "-----BEGIN EC PRIVATE KEY-----\n" +
                    "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgvYiiubZYNO1WXXi3\n" +
                    "jmGT9DLeFemvlmR1zTA0FdcSAG2gCgYIKoZIzj0DAQehRANCAATNXYa06ykwhxuy\n" +
                    "Dg+q6zsVqOLk9LtXz/1fzf9AkAVm9lBMTZAh+FRfregBgl08LATztGlTh/z0dPnp\n" +
                    "dW2jFrDn\n" +
                    "-----END EC PRIVATE KEY-----";

        PEMParser pemRd = new PEMParser(new StringReader(ecSample));

        PEMKeyPair kp = (PEMKeyPair)pemRd.readObject();

        isTrue(kp.getPublicKeyInfo() == null);
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ParserTest());
    }
}
