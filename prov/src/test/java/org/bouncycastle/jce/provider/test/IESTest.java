package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * test for ECIES - Elliptic Curve Integrated Encryption Scheme
 */
public class IESTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    IESTest()
    {
    }

    public String getName()
    {
        return "IES";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECIES", "BC");

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECParameterSpec ecSpec = new ECParameterSpec(x9.getCurve(), x9.getG(),x9.getN(), x9.getH());

        g.initialize(ecSpec, new SecureRandom());

        Cipher c1 = Cipher.getInstance("ECIES", "BC");
        Cipher c2 = Cipher.getInstance("ECIES", "BC");
        
        doTest(g, c1, c2);

        g = KeyPairGenerator.getInstance("ECIES", "BC");

        g.initialize(192, new SecureRandom());

        doTest(g, c1, c2);

        g = KeyPairGenerator.getInstance("ECIES", "BC");

        g.initialize(239, new SecureRandom());

        doTest(g, c1, c2);

        g = KeyPairGenerator.getInstance("ECIES", "BC");

        g.initialize(256, new SecureRandom());

        doTest(g, c1, c2);

        doDefTest(g, c1, c2);
        
        DHParameterSpec             dhParams = new DHParameterSpec(p512, g512);
        
        c1 = Cipher.getInstance("IES", "BC");
        c2 = Cipher.getInstance("IES", "BC");
        
        g = KeyPairGenerator.getInstance("DH", "BC");

        g.initialize(dhParams);
        
        doTest(g, c1, c2);
        
        doDefTest(g, c1, c2);

        doOutputSizeTest();
        doAlgorithmParameterTest();
    }

    private void doOutputSizeTest()
        throws Exception
    {
        final byte[] data = "Block of data to be encrypted".getBytes();

        /* Generate keys */

        final KeyPairGenerator generator = KeyPairGenerator.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        final KeyPair keyPair = generator.generateKeyPair();
        final SecureRandom random = new SecureRandom();
        final byte[] nonce = new byte[16];
        random.nextBytes(nonce);

        /* Encrypt */

        final Cipher encryptCipher = Cipher.getInstance("ECIESWITHAES-CBC", BouncyCastleProvider.PROVIDER_NAME);
        final IESParameterSpec spec = new IESParameterSpec(null, null, 128, 128, nonce);
        encryptCipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(keyPair.getPrivate(), keyPair.getPublic()), spec);

        /* Calculate the size if only doFinal was going to be called */

        int onlyFinalExpectedSize = encryptCipher.getOutputSize(data.length);

        /* Calculate the size with an update followed by an empty doFinal */

        encryptCipher.update(data);
        int updateAndFinalExpectedSize = encryptCipher.getOutputSize(0);

        isTrue(updateAndFinalExpectedSize == onlyFinalExpectedSize);

        final byte[] encrypted = new byte[updateAndFinalExpectedSize];
        int actualEncryptedSize = encryptCipher.doFinal(encrypted, 0);

        final Cipher decryptCipher = Cipher.getInstance("ECIESWITHAES-CBC", BouncyCastleProvider.PROVIDER_NAME);

        decryptCipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(keyPair.getPrivate(), keyPair.getPublic()), spec);

        /* Calculate the size if only doFinal was going to be called */

        onlyFinalExpectedSize = decryptCipher.getOutputSize(actualEncryptedSize);

        /* Calculate the size with an update followed by an empty doFinal */

        decryptCipher.update(encrypted, 0, actualEncryptedSize);
        updateAndFinalExpectedSize = decryptCipher.getOutputSize(0);
       
        isTrue(updateAndFinalExpectedSize == onlyFinalExpectedSize);
        final byte[] decrypted = new byte[updateAndFinalExpectedSize];
        final int actualDecryptedSize = decryptCipher.doFinal(decrypted, 0);

        isTrue(areEqual(data, 0, data.length, decrypted, 0, actualDecryptedSize));
    }

    private void doAlgorithmParameterTest()
        throws Exception
    {
        trySpec(new IESParameterSpec(null, null, 128, 128, Hex.decode("deafbeef")));
        trySpec(new IESParameterSpec(Hex.decode("ffff"), Hex.decode("aaaa"), 256, 128, Hex.decode("deafbeef")));
        trySpec(new IESParameterSpec(Hex.decode("ffff"), Hex.decode("aaaa"), 256, 128, Hex.decode("deafbeef"), true));
        trySpec(new IESParameterSpec(Hex.decode("ffffcc"), Hex.decode("aaaabb"), 256));
    }

    private void trySpec(IESParameterSpec spec)
        throws Exception
    {
        AlgorithmParameters alg1 = AlgorithmParameters.getInstance("IES", "BC");
        AlgorithmParameters alg2 = AlgorithmParameters.getInstance("IES", "BC");

        alg1.init(spec);

        alg2.init(alg1.getEncoded());

        IESParameterSpec iesSpec = (IESParameterSpec)alg2.getParameterSpec(IESParameterSpec.class);

        isTrue(iesSpec.getPointCompression() == spec.getPointCompression());
        isTrue(Arrays.areEqual(iesSpec.getNonce(), spec.getNonce()));
        isTrue(Arrays.areEqual(iesSpec.getDerivationV(), spec.getDerivationV()));
        isTrue(Arrays.areEqual(iesSpec.getEncodingV(), spec.getEncodingV()));
        isTrue(iesSpec.getMacKeySize() == spec.getMacKeySize());
        isTrue(iesSpec.getCipherKeySize() == spec.getCipherKeySize());
    }
    
    public void doTest(
        KeyPairGenerator g,
        Cipher           c1,
        Cipher           c2)
        throws Exception
    {
        //
        // a side
        //
        KeyPair     aKeyPair = g.generateKeyPair();
        PublicKey   aPub = aKeyPair.getPublic();
        PrivateKey  aPriv = aKeyPair.getPrivate();

        //
        // b side
        //
        KeyPair     bKeyPair = g.generateKeyPair();
        PublicKey   bPub = bKeyPair.getPublic();
        PrivateKey  bPriv = bKeyPair.getPrivate();

        //
        // stream test
        //

        IEKeySpec   c1Key = new IEKeySpec(aPriv, bPub);
        IEKeySpec   c2Key = new IEKeySpec(bPriv, aPub);

        byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

        IESParameterSpec param = new IESParameterSpec(d, e, 128);

        c1.init(Cipher.ENCRYPT_MODE, c1Key, param);

        c2.init(Cipher.DECRYPT_MODE, c2Key, param);

        byte[] message = Hex.decode("1234567890abcdef");

        int estLen1 =  c1.getOutputSize(message.length);

        byte[]   out1 = c1.doFinal(message, 0, message.length);

        if (estLen1 < out1.length)
        {
            fail("output size incorrect");
        }

        int estLen2 =  c2.getOutputSize(out1.length);

        byte[]   out2 = c2.doFinal(out1, 0, out1.length);

        if (estLen2 < out2.length)
        {
            fail("output size incorrect");
        }

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }
    }

    // Misnamed now that null parameters no longer supported
    public void doDefTest(
        KeyPairGenerator    g,
        Cipher              c1,
        Cipher              c2)
        throws Exception
    {
        //
        // a side
        //
        KeyPair     aKeyPair = g.generateKeyPair();
        PublicKey   aPub = aKeyPair.getPublic();
        PrivateKey  aPriv = aKeyPair.getPrivate();

        //
        // b side
        //
        KeyPair     bKeyPair = g.generateKeyPair();
        PublicKey   bPub = bKeyPair.getPublic();
        PrivateKey  bPriv = bKeyPair.getPrivate();

        //
        // stream test
        //
        IEKeySpec   c1Key = new IEKeySpec(aPriv, bPub);
        IEKeySpec   c2Key = new IEKeySpec(bPriv, aPub);

        byte[]  d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[]  e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };

        IESParameterSpec param = new IESParameterSpec(d, e, 128);

        c1.init(Cipher.ENCRYPT_MODE, c1Key, param);

        c2.init(Cipher.DECRYPT_MODE, c2Key, param);

        byte[] message = Hex.decode("1234567890abcdef");

        int estLen1 = c1.getOutputSize(message.length);

        byte[] out1 = c1.doFinal(message, 0, message.length);

        if (estLen1 < out1.length)
        {
            fail("output size incorrect");
        }

        int estLen2 =  c2.getOutputSize(out1.length);
        byte[] out2 = c2.doFinal(out1, 0, out1.length);

        if (estLen2 < out2.length)
        {
            fail("output size incorrect");
        }

        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }
        
        //
        // int doFinal
        //
        int len1 = c1.doFinal(message, 0, message.length, out1, 0);
        
        if (len1 != out1.length)
        {
            fail("encryption length wrong");
        }
        
        int len2 = c2.doFinal(out1, 0, out1.length, out2, 0);

        if (len2 != out2.length)
        {
            fail("decryption length wrong");
        }
        
        if (!areEqual(out2, message))
        {
            fail("stream cipher test failed");
        }
        
        //
        // int doFinal with update
        //
        len1 = c1.update(message, 0, 2, out1, 0);
        
        len1 += c1.doFinal(message, 2, message.length - 2, out1, len1);
        
        if (len1 != out1.length)
        {
            fail("update encryption length wrong");
        }
        
        len2 = c2.update(out1, 0, 2, out2, 0);
        
        len2 += c2.doFinal(out1, 2, out1.length - 2, out2, len2);

        if (len2 != out2.length)
        {
            fail("update decryption length wrong");
        }
        
        if (!areEqual(out2, message))
        {
            fail("update stream cipher test failed");
        }
    }

    public static void main(
        String[]    args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new IESTest());
    }
}
