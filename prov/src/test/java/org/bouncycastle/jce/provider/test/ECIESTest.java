package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class ECIESTest
    extends SimpleTest
{

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
        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");
        
        
        IESCipher c1 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();
        IESCipher c2 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES();
        IESParameterSpec params = new IESParameterSpec(derivation,encoding,128);

        // Testing ECIES with default curve in streaming mode
        KeyPairGenerator    g = KeyPairGenerator.getInstance("EC", "BC");
        doTest("ECIES with default", g, "ECIES", params);
        
        // Testing ECIES with 192-bit curve in streaming mode 
        g.initialize(192, new SecureRandom());
        doTest("ECIES with 192-bit", g, "ECIES", params);

        // Testing ECIES with 256-bit curve in streaming mode 
        g.initialize(256, new SecureRandom());
        doTest("ECIES with 256-bit", g, "ECIES", params);

        
        c1 = new IESCipher(new IESEngine(new ECDHBasicAgreement(), 
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));
        
        c2 = new IESCipher(new IESEngine(new ECDHBasicAgreement(), 
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));  
    
        params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("0001020304050607"));
      
        // Testing ECIES with default curve using DES
        g = KeyPairGenerator.getInstance("EC", "BC");

        // Testing ECIES with 256-bit curve using DES-CBC
        g.initialize(256, new SecureRandom());
        doTest("256-bit", g, "ECIESwithDESEDE-CBC", params);

        params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("0001020304050607"));
        g.initialize(256, new SecureRandom());
        doTest("256-bit", g, "ECIESwithDESEDE-CBC", params);

        try
        {
            params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
            g.initialize(256, new SecureRandom());
            doTest("256-bit", g, "ECIESwithDESEDE-CBC", params);
            fail("DESEDE no exception!");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!e.getMessage().equals("NONCE in IES Parameters needs to be 8 bytes long"))
            {
                fail("DESEDE wrong message!");
            }
        }

        c1 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithAESCBC();
        c2 = new org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithAESCBC();
        params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));

        // Testing ECIES with 256-bit curve using AES-CBC
        g.initialize(256, new SecureRandom());
        doTest("256-bit", g, "ECIESwithAES-CBC", params);

        params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));
        g.initialize(256, new SecureRandom());
        doTest("256-bit", g, "ECIESwithAES-CBC", params);

        try
        {
            params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
            g.initialize(256, new SecureRandom());
            doTest("256-bit", g, "ECIESwithAES-CBC", params);
            fail("AES no exception!");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!e.getMessage().equals("NONCE in IES Parameters needs to be 16 bytes long"))
            {
                fail("AES wrong message!");
            }
        }

        KeyPair       keyPair = g.generateKeyPair();
        ECPublicKey pub = (ECPublicKey)keyPair.getPublic();
        ECPrivateKey priv = (ECPrivateKey)keyPair.getPrivate();

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
            isTrue("message ", "cannot handle supplied parameter spec: NONCE in IES Parameters needs to be 16 bytes long".equals(e.getMessage()));
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

        sealedObjectTest();
    }

    private void sealedObjectTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        String toEncrypt = "Hello";

        // Check that cipher works ok
        cipher.doFinal(toEncrypt.getBytes());

        // Using a SealedObject to encrypt the same string fails with a NullPointerException
        SealedObject sealedObject = new SealedObject(toEncrypt, cipher);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        String result = (String)sealedObject.getObject(cipher);

        isTrue("result wrong", result.equals(toEncrypt));

        result = (String)sealedObject.getObject(keyPair.getPrivate());

        isTrue("result wrong", result.equals(toEncrypt));
    }

    public void doTest(
        String                testname,
        KeyPairGenerator     g,
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

        // Testing with null parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, Pub, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, Priv, c1.getParameters());

        isTrue("nonce mismatch", Arrays.areEqual(c1.getIV(), c2.getIV()));

        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
            fail(testname + " test failed with null parameters, DHAES mode false.");
    
        
        // Testing with given parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, Pub, p, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, Priv, p);
        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
            fail(testname + " test failed with non-null parameters, DHAES mode false.");
        
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
