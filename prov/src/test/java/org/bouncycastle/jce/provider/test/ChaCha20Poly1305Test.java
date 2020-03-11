package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ChaCha20Poly1305Test
    extends SimpleTest
{
    private static final String[][] TEST_VECTORS = new String[][] {
    {
        "Test Case 1",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "4c616469657320616e642047656e746c"
        + "656d656e206f662074686520636c6173"
        + "73206f66202739393a20496620492063"
        + "6f756c64206f6666657220796f75206f"
        + "6e6c79206f6e652074697020666f7220"
        + "746865206675747572652c2073756e73"
        + "637265656e20776f756c642062652069"
        + "742e",
        "50515253c0c1c2c3c4c5c6c7",
        "070000004041424344454647",
        "d31a8d34648e60db7b86afbc53ef7ec2"
        + "a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b"
        + "1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58"
        + "fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b"
        + "6116",
        "1ae10b594f09e26a7e902ecbd0600691",
    },
    };

    private boolean aeadAvailable = false;

    public String getName()
    {
        return "ChaCha20Poly1305";
    }

    public void performTest() throws Exception
    {
        try
        {
            this.getClass().getClassLoader().loadClass("javax.crypto.spec.GCMParameterSpec");
            aeadAvailable = true;
        }
        catch (ClassNotFoundException e)
        {
        }

        for (int i = 0; i < TEST_VECTORS.length; ++i)
        {
            runTestCase(TEST_VECTORS[i]);
        }

        // basic test using oids
        byte[] msg = Strings.toByteArray("Hello, world!");

        KeyGenerator keyGen = KeyGenerator.getInstance(PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305.getId(), "BC");
        Cipher encCipher = Cipher.getInstance(PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305.getId(), "BC");
        SecretKey key = keyGen.generateKey();
        encCipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] enc = encCipher.doFinal(msg);

        Cipher decCipher = Cipher.getInstance(PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305.getId(), "BC");

        decCipher.init(Cipher.DECRYPT_MODE, key, encCipher.getParameters());

        byte[] dec = decCipher.doFinal(enc);

        areEqual(msg, dec);

        // check mac failure
        byte[] faulty = new byte[enc.length];
        System.arraycopy(enc, 0, faulty, 0, enc.length - 1);

        try
        {
            decCipher.doFinal(faulty);
            fail("no exception");
        }
        catch (Exception e)
        {
            if (aeadAvailable)
            {
                if (!e.getClass().getName().equals("javax.crypto.AEADBadTagException"))
                {
                    fail("Tampered AEAD ciphertext should fail with AEADBadTagException when available.");
                }
            }
            isEquals("mac check in ChaCha20Poly1305 failed", e.getMessage());
        }

        System.arraycopy(enc, 0, faulty, 0, enc.length);
        faulty[0] ^= -1;
        decCipher.init(Cipher.DECRYPT_MODE, key, encCipher.getParameters());
        try
        {
            decCipher.doFinal(faulty);
            fail("no exception");
        }
        catch (Exception e)
        {
            if (aeadAvailable)
            {
                if (!e.getClass().getName().equals("javax.crypto.AEADBadTagException"))
                {
                    fail("Tampered AEAD ciphertext should fail with AEADBadTagException when available.");
                }
            }
            isEquals("mac check in ChaCha20Poly1305 failed", e.getMessage());
        }
        //
        // check for alg params.
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("ChaCha20-Poly1305", "BC"); // to be sure
        algorithmParameters = AlgorithmParameters.getInstance(PKCSObjectIdentifiers.id_alg_AEADChaCha20Poly1305.getId(), "BC");

        GitHub674Test();
    }

    private void checkTestCase(
        Cipher  encCipher,
        Cipher  decCipher,
        String  testName,
        byte[]  SA,
        byte[]  P,
        byte[]  C,
        byte[]  T)
        throws Exception
    {
        byte[] enc = new byte[encCipher.getOutputSize(P.length)];
        if (SA != null)
        {
            encCipher.updateAAD(SA, 0, SA.length);
        }
        int len = encCipher.update(P, 0, P.length, enc, 0);
        len += encCipher.doFinal(enc, len);

        if (enc.length != len)
        {
            fail("encryption reported incorrect length: " + testName);
        }

        //byte[] mac = encCipher.getMac();

        byte[] data = new byte[P.length];
        System.arraycopy(enc, 0, data, 0, data.length);
        byte[] tail = new byte[enc.length - P.length];
        System.arraycopy(enc, P.length, tail, 0, tail.length);

        if (!areEqual(C, data))
        {
            fail("incorrect encrypt in: " + testName);
        }

//        if (!areEqual(T, mac))
//        {
//            fail("getMac() returned wrong mac in: " + testName);
//        }

        if (!areEqual(T, tail))
        {
            fail("stream contained wrong mac in: " + testName);
        }

        byte[] dec = new byte[decCipher.getOutputSize(enc.length)];
        if (SA != null)
        {
            decCipher.updateAAD(SA, 0, SA.length);
        }
        len = decCipher.update(enc, 0, enc.length, dec, 0);
        len += decCipher.doFinal(dec, len);
       // mac = decCipher.getMac();

        data = new byte[C.length];
        System.arraycopy(dec, 0, data, 0, data.length);

        if (!areEqual(P, data))
        {
            fail("incorrect decrypt in: " + testName);
        }
    }

    private Cipher initCipher(boolean forEncryption, Key key, IvParameterSpec iv)
        throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305", "BC");

        c.init(forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, iv);
        return c;
    }

    private void runTestCase(String[] testVector)
        throws Exception
    {
        int pos = 0;
        String testName = testVector[pos++];
        byte[] K = Hex.decode(testVector[pos++]);
        byte[] P = Hex.decode(testVector[pos++]);
        byte[] A = Hex.decode(testVector[pos++]);
        byte[] N = Hex.decode(testVector[pos++]);
        byte[] C = Hex.decode(testVector[pos++]);
        byte[] T = Hex.decode(testVector[pos++]);

        runTestCase(testName, K, N, A, P, C, T);
    }

    private void runTestCase(
        String  testName,
        byte[]  K,
        byte[]  N,
        byte[]  A,
        byte[]  P,
        byte[]  C,
        byte[]  T)
        throws Exception
    {
        byte[] fa = new byte[A.length / 2];
        byte[] la = new byte[A.length - (A.length / 2)];
        System.arraycopy(A, 0, fa, 0, fa.length);
        System.arraycopy(A, fa.length, la, 0, la.length);

        runTestCase(testName + " all initial associated data", K, N, A, null, P, C, T);

        if (aeadAvailable)
        {
            runTestCase(testName + " all subsequent associated data", K, N, null, A, P, C, T);
            runTestCase(testName + " split associated data", K, N, fa, la, P, C, T);
        }
    }

    private void runTestCase(
        String  testName,
        byte[]  K,
        byte[]  N,
        byte[]  A,
        byte[]  SA,
        byte[]  P,
        byte[]  C,
        byte[]  T)
        throws Exception
    {
        SecretKeySpec keySpec = new SecretKeySpec(K, "ChaCha20");
        AEADParameterSpec parameters = new AEADParameterSpec(N, T.length * 8, A);
        Cipher encCipher = initCipher(true, keySpec, parameters);
        Cipher decCipher = initCipher(false, keySpec, parameters);
        checkTestCase(encCipher, decCipher, testName, SA, P, C, T);
        encCipher = initCipher(true, keySpec, parameters);

        AlgorithmParameters algParams = decCipher.getParameters();

        IvParameterSpec ivSpec = (IvParameterSpec)algParams.getParameterSpec(AlgorithmParameterSpec.class);

        isTrue(areEqual(ivSpec.getIV(), N));
        isTrue(areEqual(encCipher.getIV(), N));
        
        checkTestCase(encCipher, decCipher, testName + " (reused)", SA, P, C, T);
    }

    private void GitHub674Test() throws Exception
    {
        byte[] K = new byte[32];
        byte[] N = new byte[12];
        byte[] A = new byte[0];

        SecretKeySpec keySpec = new SecretKeySpec(K, "ChaCha20");
        AEADParameterSpec parameters = new AEADParameterSpec(N, 128, A);
        Cipher encCipher = initCipher(true, keySpec, parameters);

        /*
         * This resulted in a NullPointerException before fix. It depended on the update length (63
         * being less than the internal buffer size of the ChaCha20Poly1305 engine.
         */
        byte[] encrypted = encCipher.update(new byte[63]);
        isTrue(null == encrypted);
    }

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ChaCha20Poly1305Test());
    }
}
