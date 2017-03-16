package org.bouncycastle.openssl.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.DSAParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.test.SimpleTest;

public class WriterTest
    extends SimpleTest
{
    private static final SecureRandom random = new SecureRandom();

    // TODO Replace with a randomly generated key each test run?
    private static final RSAPrivateCrtKeySpec testRsaKeySpec = new RSAPrivateCrtKeySpec(
        new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
        new BigInteger("11", 16),
        new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
        new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
        new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
        new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
        new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
        new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    private static final DSAParameterSpec testDsaParams = new DSAParameterSpec(
        new BigInteger("7434410770759874867539421675728577177024889699586189000788950934679315164676852047058354758883833299702695428196962057871264685291775577130504050839126673"),
        new BigInteger("1138656671590261728308283492178581223478058193247"),
        new BigInteger("4182906737723181805517018315469082619513954319976782448649747742951189003482834321192692620856488639629011570381138542789803819092529658402611668375788410"));

    private static final PKCS8EncodedKeySpec testEcDsaKeySpec = new PKCS8EncodedKeySpec(
        Base64.decode("MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCSBU3vo7ieeKs0ABQamy/ynxlde7Ylr8HmyfLaNnMr" +
            "jAwPp9R+KMUEhB7zxSAXv9KgBwYFK4EEACKhZANiAQQyyolMpg+TyB4o9kPWqafHIOe8o9K1glus+w2sY8OIPQQWGb5i5LdAyi" +
            "/SscwU24rZM0yiL3BHodp9ccwyhLrFYgXJUOQcCN2dno1GMols5497in5gL5+zn0yMsRtyv5o=")
    );

    private static final char[] testPassword = "bouncy".toCharArray();

    private static final String[] algorithms = new String[]
    {
        "AES-128-CBC", "AES-128-CFB", "AES-128-ECB", "AES-128-OFB",
        "AES-192-CBC", "AES-192-CFB", "AES-192-ECB", "AES-192-OFB",
        "AES-256-CBC", "AES-256-CFB", "AES-256-ECB", "AES-256-OFB",
        "BF-CBC", "BF-CFB", "BF-ECB", "BF-OFB",
        "DES-CBC", "DES-CFB", "DES-ECB", "DES-OFB",
        "DES-EDE", "DES-EDE-CBC", "DES-EDE-CFB", "DES-EDE-ECB", "DES-EDE-OFB",
        "DES-EDE3", "DES-EDE3-CBC", "DES-EDE3-CFB", "DES-EDE3-ECB", "DES-EDE3-OFB",
        "RC2-CBC", "RC2-CFB", "RC2-ECB", "RC2-OFB",
        "RC2-40-CBC",
        "RC2-64-CBC",
    };

    public String getName()
    {
        return "PEMWriterTest";
    }

    public void performTest()
        throws Exception
    {
        final String provider = "BC";

        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", provider);
        dsaKpg.initialize(testDsaParams, random);

        KeyPair dsaKp = dsaKpg.generateKeyPair();
        PrivateKey testDsaKey = dsaKp.getPrivate();

        doWriteReadTest(testDsaKey, provider);
        doWriteReadTests(testDsaKey, provider, algorithms);

        KeyFactory fact = KeyFactory.getInstance("RSA", provider);
        PrivateKey testRsaKey = fact.generatePrivate(testRsaKeySpec);

        doWriteReadTest(testRsaKey, provider);
        doWriteReadTests(testRsaKey, provider, algorithms);

        fact = KeyFactory.getInstance("ECDSA", provider);
        PrivateKey testEcDsaKey = fact.generatePrivate(testEcDsaKeySpec);

        doWriteReadTest(testEcDsaKey, provider);
        doWriteReadTests(testEcDsaKey, provider, algorithms);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(239);

        PrivateKey privKey = kpGen.generateKeyPair().getPrivate();

        doWriteReadTest(privKey, provider);
        doWriteReadTests(privKey, "BC", algorithms);

        // override test
        JcaPEMWriter pWrt = new JcaPEMWriter(new OutputStreamWriter(new ByteArrayOutputStream()));

        Object o = new PemObject("FRED", new byte[100]);
        pWrt.writeObject(o);

        pWrt.close();
    }

    private void doWriteReadTests(
        PrivateKey  akp,
        String      provider,
        String[]    algorithms)
        throws IOException
    {
        for (int i = 0; i < algorithms.length; ++i)
        {
            doWriteReadTest(akp, provider, algorithms[i]);
        }
    }

    private void doWriteReadTest(
        PrivateKey  akp,
        String      provider)
        throws IOException
    {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pw = new JcaPEMWriter(sw);

        pw.writeObject(akp);
        pw.close();

        String data = sw.toString();

        PEMParser pr = new PEMParser(new StringReader(data));

        Object o = pr.readObject();

        if (o == null || !(o instanceof PEMKeyPair))
        {
            fail("Didn't find OpenSSL key");
        }

        KeyPair kp = new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair)o);
        PrivateKey privKey = kp.getPrivate();

        if (!akp.equals(privKey))
        {
            fail("Failed to read back test");
        }
    }

    private void doWriteReadTest(
        PrivateKey  akp,
        String      provider,
        String      algorithm)
        throws IOException
    {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pw = new JcaPEMWriter(sw);

        pw.writeObject(new JcaMiscPEMGenerator(akp, new JcePEMEncryptorBuilder(algorithm).setSecureRandom(random).build(testPassword)));
        pw.close();

        String data = sw.toString();

        PEMParser pRaw = new PEMParser(new StringReader(data));
        PemObject pemObject = pRaw.readPemObject();

        List headers = pemObject.getHeaders();

        for (int i = 0; i != headers.size(); i++)
        {
            PemHeader pemH = (PemHeader)headers.get(i);

            if (pemH.getName().equals("DEK-Info"))
            {
                String v = pemH.getValue();
                for (int j = 0; j != v.length(); j++)
                {
                    if (v.charAt(j) >= 'a' && v.charAt(j) <= 'f')
                    {
                        fail("lower case detected in DEK-Info: " + v);
                    }
                }
            }
        }

        PEMParser pr = new PEMParser(new StringReader(data));

        Object o = pr.readObject();

        if (o == null || !(o instanceof PEMEncryptedKeyPair))
        {
            fail("Didn't find OpenSSL key");
        }

        KeyPair kp = new JcaPEMKeyConverter().setProvider("BC").getKeyPair(((PEMEncryptedKeyPair)o).decryptKeyPair(new JcePEMDecryptorProviderBuilder().setProvider("BC").build(testPassword)));
        PrivateKey privKey = kp.getPrivate();

        if (!akp.equals(privKey))
        {
            fail("Failed to read back test key encoded with: " + algorithm);
        }

        kp = new JcaPEMKeyConverter().setProvider("BC").getKeyPair(((PEMEncryptedKeyPair)o).decryptKeyPair(new BcPEMDecryptorProvider(testPassword)));
        privKey = kp.getPrivate();

        if (!akp.equals(privKey))
        {
            fail("BC failed to read back test key encoded with: " + algorithm);
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new WriterTest());
    }
}
