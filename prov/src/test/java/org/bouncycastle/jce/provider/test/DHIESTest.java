package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test for DHIES - Diffie-Hellman Integrated Encryption Scheme
 */
public class DHIESTest
    extends SimpleTest
{
    // Oakley group 2 - RFC 5996
    BigInteger p1024 = new BigInteger(
                    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                    "FFFFFFFFFFFFFFFF",16);

    BigInteger g1024 = new BigInteger("2",16);

    BigInteger p2048 = new BigInteger("95475cf5d93e596c3fcd1d902add02f427f5f3c7210313bb45fb4d5b" +
                                "b2e5fe1cbd678cd4bbdd84c9836be1f31c0777725aeb6c2fc38b85f4" +
                                "8076fa76bcd8146cc89a6fb2f706dd719898c2083dc8d896f84062e2" +
                                "c9c94d137b054a8d8096adb8d51952398eeca852a0af12df83e475aa" +
                                "65d4ec0c38a9560d5661186ff98b9fc9eb60eee8b030376b236bc73b" +
                                "e3acdbd74fd61c1d2475fa3077b8f080467881ff7e1ca56fee066d79" +
                                "506ade51edbb5443a563927dbc4ba520086746175c8885925ebc64c6" +
                                "147906773496990cb714ec667304e261faee33b3cbdf008e0c3fa906" +
                                "50d97d3909c9275bf4ac86ffcb3d03e6dfc8ada5934242dd6d3bcca2" +
                                "a406cb0b", 16);

    BigInteger g2048 = new BigInteger("42debb9da5b3d88cc956e08787ec3f3a09bba5f48b889a74aaf53174" +
                                "aa0fbe7e3c5b8fcd7a53bef563b0e98560328960a9517f4014d3325f" +
                                "c7962bf1e049370d76d1314a76137e792f3f0db859d095e4a5b93202" +
                                "4f079ecf2ef09c797452b0770e1350782ed57ddf794979dcef23cb96" +
                                "f183061965c4ebc93c9c71c56b925955a75f94cccf1449ac43d586d0" +
                                "beee43251b0b2287349d68de0d144403f13e802f4146d882e057af19" +
                                "b6f6275c6676c8fa0e3ca2713a3257fd1b27d0639f695e347d8d1cf9" +
                                "ac819a26ca9b04cb0eb9b7b035988d15bbac65212a55239cfc7e58fa" +
                                "e38d7250ab9991ffbc97134025fe8ce04c4399ad96569be91a546f49" +
                                "78693c7a", 16);

    DHParameterSpec param1024 = new DHParameterSpec(p1024, g1024);

    DHParameterSpec param2048 = new DHParameterSpec(p2048, g2048);

    DHIESTest()
    {
    }

    public String getName()
    {
        return "DHIES";
    }

    public void performTest()
        throws Exception
    {
        byte[] derivation = Hex.decode("202122232425262728292a2b2c2d2e2f");
        byte[] encoding   = Hex.decode("303132333435363738393a3b3c3d3e3f");

        
        IESCipher c1 = new org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher.IES();
        IESCipher c2 = new org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher.IES();
        IESParameterSpec params = new IESParameterSpec(derivation,encoding,128);

        // Testing DHIES with default prime in streaming mode
        KeyPairGenerator    g = KeyPairGenerator.getInstance("DH", "BC");
        KeyPairGenerator    g512 = KeyPairGenerator.getInstance("DH", "BC");

        g.initialize(param1024);

        doTest("DHIES with default", g, "DHIES", params);
        
        // Testing DHIES with 512-bit prime in streaming mode
        g512.initialize(512, new SecureRandom());
        doTest("DHIES with 512-bit", g512, "DHIES", params);

        // Testing ECIES with 1024-bit prime in streaming mode 
        g.initialize(param1024, new SecureRandom());
        doTest("DHIES with 1024-bit", g, "DHIES", params);

        c1 = new IESCipher(new IESEngine(new DHBasicAgreement(), 
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));
        
        c2 = new IESCipher(new IESEngine(new DHBasicAgreement(), 
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));  
    
        params = new IESParameterSpec(derivation, encoding, 128, 192, Hex.decode("0001020304050607"));
      
        // Testing DHIES with default prime (2048) using DESEDE
        g = KeyPairGenerator.getInstance("DH", "BC");
        g.initialize(param2048, new SecureRandom());

        doTest("DHIESwithDES default", g, "DHIESwithDESEDE-CBC", params);
        
        // Testing DHIES with 512-bit prime using DESEDE
        doTest("DHIESwithDES 512-bit", g512, "DHIESwithDESEDE-CBC", params);
        
        // Testing DHIES with 1024-bit prime using DESEDE
        g.initialize(param1024, new SecureRandom());
        doTest("DHIESwithDES 1024-bit", g, "DHIESwithDESEDE-CBC", params);

        g = KeyPairGenerator.getInstance("DH", "BC");
        g.initialize(param1024);

        c1 = new IESCipher.IESwithAESCBC();
        c2 = new IESCipher.IESwithAESCBC();
        params = new IESParameterSpec(derivation, encoding, 128, 128, Hex.decode("00010203040506070001020304050607"));
        
        // Testing DHIES with default prime using AES
        doTest("DHIESwithAES default", g, "DHIESwithAES-CBC", params);
        
        // Testing DHIES with 512-bit prime using AES
        doTest("DHIESwithAES 512-bit", g512, "DHIESwithAES-CBC", params);
        
        // Testing DHIES with 1024-bit prime using AES
        g.initialize(param1024, new SecureRandom());
        doTest("DHIESwithAES 1024-bit", g, "DHIESwithAES-CBC", params);

        KeyPair       keyPair = g.generateKeyPair();
        DHPublicKey   pub = (DHPublicKey)keyPair.getPublic();
        DHPrivateKey  priv = (DHPrivateKey)keyPair.getPrivate();

        Cipher c = Cipher.getInstance("DHIESwithAES-CBC", "BC");

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
  
        Cipher        c1 = Cipher.getInstance(cipher, "BC");
        Cipher        c2 = Cipher.getInstance(cipher, "BC");
        // Generate static key pair
        KeyPair       keyPair = g.generateKeyPair();
        DHPublicKey   pub = (DHPublicKey)keyPair.getPublic();
        DHPrivateKey  priv = (DHPrivateKey)keyPair.getPrivate();

        // Testing with default parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, pub, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, c1.getParameters());

        isTrue("nonce mismatch", Arrays.areEqual(c1.getIV(), c2.getIV()));

        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
        {
            fail(testname + " test failed with default parameters, DHAES mode false.");
        }
        
        // Testing with given parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, pub, p, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, p);
        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
            fail(testname + " test failed with non-null parameters, DHAES mode false.");
        
        // Testing with null parameters and DHAES mode on
        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
        c1.init(Cipher.ENCRYPT_MODE, pub, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, c1.getParameters(), new SecureRandom());
        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
            fail(testname + " test failed with null parameters, DHAES mode true.");
     
        
        // Testing with given parameters and DHAES mode on
        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");

        c1.init(Cipher.ENCRYPT_MODE, pub, p, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, p, new SecureRandom());

        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
            fail(testname + " test failed with non-null parameters, DHAES mode true.");

        //
        // corrupted data test
        //
        byte[] tmp = new byte[out1.length];
        for (int i = 0; i != out1.length; i++)
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

        runTest(new DHIESTest());
    }
}
