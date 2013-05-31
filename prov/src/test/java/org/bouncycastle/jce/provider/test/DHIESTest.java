package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;
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

    DHParameterSpec param = new DHParameterSpec(p1024, g1024);

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

        g.initialize(param);

        doTest("DHIES with default", g, "DHIES", params);
        
        // Testing DHIES with 512-bit prime in streaming mode
        g.initialize(512, new SecureRandom());
        doTest("DHIES with 512-bit", g, "DHIES", params);

        // Testing ECIES with 1024-bit prime in streaming mode 
        g.initialize(1024, new SecureRandom());
        doTest("DHIES with 1024-bit", g, "DHIES", params);

        c1 = new IESCipher(new IESEngine(new DHBasicAgreement(), 
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));
        
        c2 = new IESCipher(new IESEngine(new DHBasicAgreement(), 
                new KDF2BytesGenerator(new SHA1Digest()),
                new HMac(new SHA1Digest()),
                new PaddedBufferedBlockCipher(new DESEngine())));  
    
        params = new IESParameterSpec(derivation, encoding, 128, 192);
      
        // Testing DHIES with default prime using DESEDE
        g = KeyPairGenerator.getInstance("DH", "BC");
        doTest("DHIESwithDES default", g, "DHIESwithDESEDE", params);
        
        // Testing DHIES with 512-bit prime using DESEDE
        g.initialize(512, new SecureRandom());
        doTest("DHIESwithDES 512-bit", g, "DHIESwithDESEDE", params);
        
        // Testing DHIES with 1024-bit prime using DESEDE
        g.initialize(1024, new SecureRandom());
        doTest("DHIESwithDES 1024-bit", g, "DHIESwithDESEDE", params);

        g = KeyPairGenerator.getInstance("DH", "BC");
        g.initialize(param);

        c1 = new IESCipher.IESwithAES();
        c2 = new IESCipher.IESwithAES();
        params = new IESParameterSpec(derivation, encoding, 128, 128);
        
        // Testing DHIES with default curve using AES
        doTest("DHIESwithAES default", g, "DHIESwithAES", params);
        
        // Testing DHIES with 512-bit curve using AES
        g.initialize(512, new SecureRandom());
        doTest("DHIESwithAES 512-bit", g, "DHIESwithAES", params);
        
        // Testing DHIES with 1024-bit curve using AES
        g.initialize(1024, new SecureRandom());
        doTest("DHIESwithAES 1024-bit", g, "DHIESwithAES", params);
        
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
  
        Cipher        c1 = Cipher.getInstance(cipher, "BC");
        Cipher        c2 = Cipher.getInstance(cipher, "BC");
        // Generate static key pair
        KeyPair       keyPair = g.generateKeyPair();
        DHPublicKey   pub = (DHPublicKey)keyPair.getPublic();
        DHPrivateKey  priv = (DHPrivateKey)keyPair.getPrivate();
       

        // Testing with null parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, pub, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, new SecureRandom());
        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
        {
            fail(testname + " test failed with null parameters, DHAES mode false.");
        }
    
        
        // Testing with given parameters and DHAES mode off
        c1.init(Cipher.ENCRYPT_MODE, pub, p, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, p, new SecureRandom());
        out1 = c1.doFinal(message, 0, message.length);
        out2 = c2.doFinal(out1, 0, out1.length);
        if (!areEqual(out2, message))
            fail(testname + " test failed with non-null parameters, DHAES mode false.");
        
        // Testing with null parameters and DHAES mode on
        c1 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
        c2 = Cipher.getInstance(cipher + "/DHAES/PKCS7Padding","BC");
        c1.init(Cipher.ENCRYPT_MODE, pub, new SecureRandom());
        c2.init(Cipher.DECRYPT_MODE, priv, new SecureRandom());
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
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DHIESTest());
    }
}
