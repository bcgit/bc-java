package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.spec.IESKEMParameterSpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class ECIESTest
    extends SimpleTest
{
    private static final String[] streamCiphers = new String[]{
            "ECIES", "ECIESwithSHA1", "ECIESwithSHA256", "ECIESwithSHA384", "ECIESwithSHA512"};

    private static final String[] aesCiphers = new String[]{
            "ECIESwithAES-CBC", "ECIESwithSHA1andAES-CBC", "ECIESwithSHA256andAES-CBC",
            "ECIESwithSHA384andAES-CBC", "ECIESwithSHA512andAES-CBC"};

    private static final String[] desedeCiphers = new String[]{
            "ECIESwithDESEDE-CBC", "ECIESwithSHA1andDESEDE-CBC", "ECIESwithSHA256andDESEDE-CBC",
            "ECIESwithSHA384andDESEDE-CBC", "ECIESwithSHA512andDESEDE-CBC"};

    ECIESTest()
    {
    }

    public String getName()
    {
        return "ECIES";
    }

    public void performTest()
        throws Exception
    {
        etsiEciesTest();
        etsiEciesRandomTest();
        etsiEciesUncompressedRandomTest();

        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");

        IESCipher c1 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();
        IESCipher c2 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();

        c1 = new IESCipher(new IESEngine(new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));

        c2 = new IESCipher(new IESEngine(new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));

        c1 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithAESCBC();
        c2 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithAESCBC();

        // Testing ECIES with default curve in streaming mode
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        for (int i = 0; i != streamCiphers.length; i++)
        {
            String cipher = streamCiphers[i];
            IESParameterSpec params = new IESParameterSpec(derivation, encoding,128);
            doTest(cipher + " with default", g, cipher, params);

            // Testing ECIES with 192-bit curve in streaming mode
            g.initialize(192, new SecureRandom());
            doTest(cipher + " with 192-bit", g, cipher, params);

            // Testing ECIES with 256-bit curve in streaming mode
            g.initialize(256, new SecureRandom());
            doTest(cipher + " with 256-bit", g, cipher, params);
        }

        // Testing ECIES with default curve using DES
        g = KeyPairGenerator.getInstance("EC", "BC");

        // Testing ECIES with 256-bit curve using DES-CBC
        for (int i = 0; i != desedeCiphers.length; i++)
        {
            String cipher = desedeCiphers[i];
            IESParameterSpec params = new IESParameterSpec(
                    derivation, encoding, 128, 128, Hex.decode("0001020304050607"));
            g.initialize(256, new SecureRandom());
            doTest(cipher + " with 256-bit", g, cipher, params);

            params = new IESParameterSpec(
                    derivation, encoding, 128, 128, Hex.decode("0001020304050607"));
            g.initialize(256, new SecureRandom());
            doTest(cipher + " with 256-bit", g, cipher, params);

            try
            {
                params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
                g.initialize(256, new SecureRandom());
                doTest(cipher + " with 256-bit", g, cipher, params);
                fail("DESEDE no exception!");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                if (!e.getMessage().equals("NONCE in IES Parameters needs to be 8 bytes long"))
                {
                    fail("DESEDE wrong message!");
                }
            }
        }

        // Testing ECIES with 256-bit curve using AES-CBC
        for (int i = 0; i != aesCiphers.length; i++)
        {
            String cipher = aesCiphers[i];
            IESParameterSpec params = new IESParameterSpec(
                    derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));
            g.initialize(256, new SecureRandom());
            doTest(cipher + " with 256-bit", g, cipher, params);

            params = new IESParameterSpec(
                    derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));
            g.initialize(256, new SecureRandom());
            doTest(cipher + " with 256-bit", g, cipher, params);

            try
            {
                params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
                g.initialize(256, new SecureRandom());
                doTest(cipher + " with 256-bit", g, cipher, params);
                fail("AES no exception!");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                if (!e.getMessage().equals("NONCE in IES Parameters needs to be 16 bytes long"))
                {
                    fail("AES wrong message!");
                }
            }

            KeyPair keyPair = g.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

            Cipher c = Cipher.getInstance("ECIESwithAES-CBC", "BC");
            try
            {
                c.init(Cipher.ENCRYPT_MODE, pub, new IESParameterSpec(derivation, encoding, 128, 128, null));
                fail("no exception");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                isTrue("message ", "NONCE in IES Parameters needs to be 16 bytes long".equals(e.getMessage()));
            }

            try
            {
                c.init(Cipher.DECRYPT_MODE, priv);
                fail("no exception");
            }
            catch (IllegalArgumentException e)
            {
//                isTrue("message ", "cannot handle supplied parameter spec: NONCE in IES Parameters needs to be 16 bytes long".equals(e.getMessage()));
                isTrue("message ", "cannot handle supplied parameter spec: must be passed IES parameters".equals(e.getMessage()));
            }

            try
            {
                c.init(Cipher.DECRYPT_MODE, priv, new IESParameterSpec(derivation, encoding, 128, 128, null));
                fail("no exception");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                isTrue("message ", "NONCE in IES Parameters needs to be 16 bytes long".equals(e.getMessage()));
            }
        }

        sealedObjectTest();
    }

    private void etsiEciesTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"), new FixedSecureRandom(Hex.decode("06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86")));

        KeyPair kp = kpGen.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("EC", "BC");

        X9ECParameters x9ECParameters = ECNamedCurveTable.getByName("P-256");
        ECCurve curve = x9ECParameters.getCurve();
        PublicKey pKey = kFact.generatePublic(
            new ECPublicKeySpec(curve.decodePoint(Hex.decode("03996da81b76fbdcaae0289abddfaf2b7198456dbe5495e58c7c61e32a2c2610ca")),
                new ECNamedCurveParameterSpec("P-256", curve, x9ECParameters.getG(), x9ECParameters.getN())));

        Cipher etsiKem = Cipher.getInstance("ETSIKEMwithSHA256", "BC");

        etsiKem.init(Cipher.UNWRAP_MODE, kp.getPrivate(), new IESKEMParameterSpec(Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E")));

        SecretKey k = (SecretKey)etsiKem.unwrap(Hex.decode("03996da81b76fbdcaae0289abddfaf2b7198456dbe5495e58c7c61e32a2c2610ca49a6e39470e44e37f302da99da444426f368211d919a06c57b574647b97ccc51"), "AES", Cipher.SECRET_KEY);
        // check the decryption
        Cipher ccm = Cipher.getInstance("CCM", "BC");

        ccm.init(Cipher.DECRYPT_MODE, k, new AEADParameterSpec(
             Hex.decode("eaf3a6736b866446b1501313"), 128));

        byte[] pt = ccm.doFinal(Hex.decode("1e56af1083537123946957844cc5906698a777dddc317966a3920e16cfad39c6977f28156bd849b57e33b2a9abd1caa8a08520084214b865a355f6d274c3a64694b81b605b729c2a6fbe88c561e591a055713698d40cabe196b1c96fefccc05f977beef6ce3528950c0e05f1c43749fd06114641c0442d0c952eb2eb0fa6b6f0b3142c6a7e170c2520edf79076c0b6000d4216af50a72955a28e48b0d5ba14b05e3ed4e5220c8bcc207070f6738b3b6ecabe056584b971df2a515bccd129bb614d2666a461542fa4c4d25a67a91bacda14fba0310cb937fa9d5d3351f17272eef2b6e492c3d7a02df81befed05139ce58a9c7f5d2f24f8acd99c4f8a8adbdd6a535f89a8a406430d3a335caa563b35bbb0733379d58f9056d017fdd7"));
    }

    private void etsiEciesRandomTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kp = kpGen.generateKeyPair();

        SecretKey k = new SecretKeySpec(Hex.decode("d311371e8373bea1027e6ae573d6f1dd"), "AES");

        Cipher etsiKem = Cipher.getInstance("ETSIKEMwithSHA256", "BC");

        etsiKem.init(Cipher.WRAP_MODE, kp.getPublic(), new IESKEMParameterSpec(Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E"), true));

        byte[] enc = etsiKem.wrap(k);

        etsiKem.init(Cipher.UNWRAP_MODE, kp.getPrivate(), new IESKEMParameterSpec(Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E"), true));

        SecretKey decK = (SecretKey)etsiKem.unwrap(enc, "AES", Cipher.SECRET_KEY);

        isTrue(Arrays.areEqual(k.getEncoded(), decK.getEncoded()));
    }

    private void etsiEciesUncompressedRandomTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kp = kpGen.generateKeyPair();

        SecretKey k = new SecretKeySpec(Hex.decode("d311371e8373bea1027e6ae573d6f1dd"), "AES");

        Cipher etsiKem = Cipher.getInstance("ETSIKEMwithSHA256", "BC");

        etsiKem.init(Cipher.WRAP_MODE, kp.getPublic(), new IESKEMParameterSpec(Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B511500"), false));

        byte[] enc = etsiKem.wrap(k);

        etsiKem.init(Cipher.UNWRAP_MODE, kp.getPrivate(), new IESKEMParameterSpec(Hex.decode("843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B511500"), false));

        SecretKey decK = (SecretKey)etsiKem.unwrap(enc, "AES", Cipher.SECRET_KEY);

        isTrue(Arrays.areEqual(k.getEncoded(), decK.getEncoded()));
    }

    private void sealedObjectTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");
        IESParameterSpec params = new IESParameterSpec(derivation, encoding, 128);

        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), params);

        String toEncrypt = "Hello";

        // Check that cipher works ok
        cipher.doFinal(toEncrypt.getBytes());

        // Using a SealedObject to encrypt the same string fails with a NullPointerException
        SealedObject sealedObject = new SealedObject(toEncrypt, cipher);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), params);

        String result = (String)sealedObject.getObject(cipher);

        isTrue("result wrong", result.equals(toEncrypt));

        result = (String)sealedObject.getObject(keyPair.getPrivate());

        isTrue("result wrong", result.equals(toEncrypt));
    }

    public void doTest(
        String              testname,
        KeyPairGenerator    g,
        String              cipher,
        IESParameterSpec    p)
        throws Exception
    {
        byte[] message = Hex.decode("0102030405060708090a0b0c0d0e0f10111213141516");
        byte[] out1, out2;

        // Generate static key pair
        KeyPair     KeyPair = g.generateKeyPair();
        ECPublicKey   Pub = (ECPublicKey) KeyPair.getPublic();
        ECPrivateKey  Priv = (ECPrivateKey) KeyPair.getPrivate();

        Cipher c1 = Cipher.getInstance(cipher);
        Cipher c2 = Cipher.getInstance(cipher);

        // Null parameters no longer supported
//        c1.init(Cipher.ENCRYPT_MODE, Pub, new SecureRandom());
//        c2.init(Cipher.DECRYPT_MODE, Priv, c1.getParameters());
//
//        isTrue("nonce mismatch", Arrays.areEqual(c1.getIV(), c2.getIV()));
//
//        out1 = c1.doFinal(message, 0, message.length);
//        out2 = c2.doFinal(out1, 0, out1.length);
//        if (!areEqual(out2, message))
//        {
//            fail(testname + " test failed with null parameters, DHAES mode false.");
//        }

        // Testing with given parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, Pub, p, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, Priv, p);
        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
        {
            fail(testname + " test failed with non-null parameters, DHAES mode false.");
        }

        isTrue(c1.getOutputSize(message.length) == out1.length);
        isTrue(c2.getOutputSize(out1.length) >= out2.length);
        
        //
        // corrupted data test
        //
        int offset = out1.length - (message.length + 8);
        byte[] tmp = new byte[out1.length];
        for (int i = offset; i != out1.length; i++)
        {
            System.arraycopy(out1, 0, tmp, 0, tmp.length);
            tmp[i] = (byte)~tmp[i];

            try
            {
                c2.doFinal(tmp, 0, tmp.length);
                fail("decrypted corrupted data");
            }
            catch (BadPaddingException e)
            {
                isTrue("wrong message: " + e.getMessage(), "unable to process block".equals(e.getMessage()));
            }
        }
// TODO: DHAES mode is not currently implemented, perhaps it shouldn't be...
//        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
//        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
//
//        // Testing with null parameters and DHAES mode on
//        c1.init(Cipher.ENCRYPT_MODE, Pub, new SecureRandom());
//        c2.init(Cipher.DECRYPT_MODE, Priv, new SecureRandom());
//
//        out1 = c1.doFinal(message, 0, message.length);
//        out2 = c2.doFinal(out1, 0, out1.length);
//        if (!areEqual(out2, message))
//            fail(testname + " test failed with null parameters, DHAES mode true.");
//
//        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding");
//        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding");
//
//        // Testing with given parameters and DHAES mode on
//        c1.init(Cipher.ENCRYPT_MODE, Pub, p, new SecureRandom());
//        c2.init(Cipher.DECRYPT_MODE, Priv, p, new SecureRandom());
//
//        out1 = c1.doFinal(message, 0, message.length);
//        out2 = c2.doFinal(out1, 0, out1.length);
//        if (!areEqual(out2, message))
//            fail(testname + " test failed with non-null parameters, DHAES mode true.");
        
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ECIESTest());
    }
}
