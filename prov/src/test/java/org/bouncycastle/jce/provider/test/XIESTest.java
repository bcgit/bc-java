package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for XIES - Elliptic Curve Integrated Encryption Scheme
 */
public class XIESTest
    extends SimpleTest
{
    private static final String[] streamCiphers = new String[]{
            "XIES", "XIESwithSHA1", "XIESwithSHA256", "XIESwithSHA384", "XIESwithSHA512"};

    private static final String[] aesCiphers = new String[]{
            "XIESwithAES-CBC", "XIESwithSHA1andAES-CBC", "XIESwithSHA256andAES-CBC",
            "XIESwithSHA384andAES-CBC", "XIESwithSHA512andAES-CBC"};

    XIESTest()
    {
    }

    public String getName()
    {
        return "XIES";
    }

    public void performTest()
        throws Exception
    {
        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");

        // Testing XIES in streaming mode
        KeyPairGenerator g25519 = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPairGenerator g448 = KeyPairGenerator.getInstance("X448", "BC");

        for (int i = 0; i != streamCiphers.length; i++)
        {
            String cipher = streamCiphers[i];
            // Testing XIES with X25519 curve in streaming mode
            IESParameterSpec params = new IESParameterSpec(derivation, encoding,128);
            doTest(cipher + " with X25519", g25519, cipher, params);

            // Testing XIES with X448 curve in streaming mode
            params = new IESParameterSpec(derivation, encoding,128);
            doTest(cipher + " with X448", g448, cipher, params);
        }

        // Testing XIES using AES-CBC
        for (int i = 0; i != aesCiphers.length; i++)
        {
            String cipher = aesCiphers[i];
            IESParameterSpec params = new IESParameterSpec(
                    derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));
            doTest(cipher + " with X25519", g25519, cipher, params);

            params = new IESParameterSpec(
                    derivation, encoding, 128, 128, Hex.decode("000102030405060708090a0b0c0d0e0f"));
            doTest(cipher + " with X448", g448, cipher, params);

            try
            {
                params = new IESParameterSpec(derivation, encoding, 128, 128, new byte[10]);
                doTest(cipher + " with X25519", g25519, cipher, params);
                fail("AES no exception!");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                if (!e.getMessage().equals("NONCE in IES Parameters needs to be 16 bytes long"))
                {
                    fail("AES wrong message!");
                }
            }

            KeyPair keyPair = g25519.generateKeyPair();
            PublicKey pub = keyPair.getPublic();
            PrivateKey priv = keyPair.getPrivate();

            Cipher c = Cipher.getInstance("XIESwithAES-CBC", "BC");
            try
            {
                c.init(Cipher.ENCRYPT_MODE, pub, new IESParameterSpec(derivation, encoding, 128, 128, null));
                fail("no exception");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                isTrue("message ", "NONCE in IES Parameters needs to be 16 bytes long".equals(e.getMessage()));
            }

            try {
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

    private void sealedObjectTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "BC");
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");
        IESParameterSpec params = new IESParameterSpec(derivation, encoding,128);

        Cipher cipher = Cipher.getInstance("XIES", "BC");
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
        KeyPair KeyPair = g.generateKeyPair();
        PublicKey Pub = KeyPair.getPublic();
        PrivateKey  Priv = KeyPair.getPrivate();

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
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new XIESTest());
    }
}
