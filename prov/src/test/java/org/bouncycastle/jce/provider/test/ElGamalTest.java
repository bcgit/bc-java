package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ElGamalTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    public String getName()
    {
        return "ElGamal";
    }

    private void testGP(
        int         size,
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
        throws Exception
    {
        DHParameterSpec  elParams = new DHParameterSpec(p, g, privateValueSize);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        byte[]           in = "This is a test".getBytes();

        keyGen.initialize(elParams);
        
        KeyPair         keyPair = keyGen.generateKeyPair();
        SecureRandom    rand = new SecureRandom();

        checkKeySize(privateValueSize, keyPair);

        Cipher  cipher = Cipher.getInstance("ElGamal", "BC");
        
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);
        
        if (cipher.getOutputSize(in.length) != (size / 8) * 2)
        {
            fail("getOutputSize wrong on encryption");
        }

        byte[]  out = cipher.doFinal(in);
        
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        
        if (cipher.getOutputSize(out.length) != (size / 8) - 1)
        {
            fail("getOutputSize wrong on decryption");
        }
        
        //
        // No Padding - maximum length
        //
        byte[]  modBytes = ((DHPublicKey)keyPair.getPublic()).getParams().getP().toByteArray();
        byte[]  maxInput = new byte[modBytes.length - 1];

        maxInput[0] |= 0x7f;

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);

        out = cipher.doFinal(maxInput);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        out = cipher.doFinal(out);

        if (!areEqual(out, maxInput))
        {
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(maxInput)) + " got " + new String(Hex.encode(out)));
        }

        //
        // encrypt/decrypt
        //

        Cipher  c1 = Cipher.getInstance("ElGamal", "BC");
        Cipher  c2 = Cipher.getInstance("ElGamal", "BC");

        c1.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);

        byte[]  out1 = c1.doFinal(in);

        c2.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[]  out2 = c2.doFinal(out1);

        if (!areEqual(in, out2))
        {
            fail(size + " encrypt test failed");
        }
        
        //
        // encrypt/decrypt with update
        //
        int outLen = c1.update(in, 0, 2, out1, 0);
        
        outLen += c1.doFinal(in, 2, in.length - 2, out1, outLen);

        out2 = new byte[c2.getOutputSize(out1.length)];

        outLen = c2.update(out1, 0, 2, out2, 0);
        
        outLen += c2.doFinal(out1, 2, out1.length - 2, out2, outLen);

        if (!areEqual(in, Arrays.copyOfRange(out2, 0, outLen)))
        {
            fail(size + " encrypt with update test failed");
        }

        //
        // public key encoding test
        //
        byte[]                  pubEnc = keyPair.getPublic().getEncoded();
        KeyFactory              keyFac = KeyFactory.getInstance("ElGamal", "BC");
        X509EncodedKeySpec      pubX509 = new X509EncodedKeySpec(pubEnc);
        DHPublicKey             pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
        DHParameterSpec         spec = pubKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit public key encoding/decoding test failed on parameters");
        }

        if (!((DHPublicKey)keyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key encoding/decoding test failed on y value");
        }

        //
        // public key serialisation test
        //
        pubKey = (DHPublicKey)serializeDeserialize(keyPair.getPublic());
        spec = pubKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit public key serialisation test failed on parameters");
        }

        if (!((DHPublicKey)keyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key serialisation test failed on y value");
        }

        if (!keyPair.getPublic().equals(pubKey))
        {
            fail("equals test failed");
        }

        if (keyPair.getPublic().hashCode() != pubKey.hashCode())
        {
            fail("hashCode test failed");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = keyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        DHPrivateKey        privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

        spec = privKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit private key encoding/decoding test failed on parameters");
        }

        if (!((DHPrivateKey)keyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key encoding/decoding test failed on y value");
        }

        //
        // private key serialisation test
        //
        privKey = (DHPrivateKey)serializeDeserialize(keyPair.getPrivate());
        spec = privKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit private key serialisation test failed on parameters");
        }

        if (!((DHPrivateKey)keyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key serialisation test failed on y value");
        }

        if (!keyPair.getPrivate().equals(privKey))
        {
            fail("equals test failed");
        }

        if (keyPair.getPrivate().hashCode() != privKey.hashCode())
        {
            fail("hashCode test failed");
        }

        if (!(privKey instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }
    }

    private Object serializeDeserialize(Object o)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(o);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        return oIn.readObject();
    }

    private void checkKeySize(int privateValueSize, KeyPair aKeyPair)
    {
        if (privateValueSize != 0)
        {
            DHPrivateKey key = (DHPrivateKey)aKeyPair.getPrivate();

            if (key.getX().bitLength() != privateValueSize)
            {
                fail("limited key check failed for key size " + privateValueSize);
            }
        }
    }

    private void testRandom(
        int         size)
        throws Exception
    {
        AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
        a.init(size, new SecureRandom());
        AlgorithmParameters params = a.generateParameters();

        byte[] encodeParams = params.getEncoded();

        AlgorithmParameters a2 = AlgorithmParameters.getInstance("ElGamal", "BC");
        a2.init(encodeParams);

        // a and a2 should be equivalent!
        byte[] encodeParams_2 = a2.getEncoded();

        if (!areEqual(encodeParams, encodeParams_2))
        {
            fail(this.getName() + ": encode/decode parameters failed");
        }

        DHParameterSpec elP = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

        testGP(size, 0, elP.getG(), elP.getP());
    }

    private void testDefault(
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
        throws Exception
    {
        DHParameterSpec  elParams = new DHParameterSpec(p, g, privateValueSize);
        int              size = p.bitLength();

        new BouncyCastleProvider().setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, elParams);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ElGamal", "BC");
        byte[]           in = "This is a test".getBytes();

        keyGen.initialize(p.bitLength());

        KeyPair         keyPair = keyGen.generateKeyPair();

        new BouncyCastleProvider().setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, elParams);

        SecureRandom    rand = new SecureRandom();

        checkKeySize(privateValueSize, keyPair);

        Cipher  cipher = Cipher.getInstance("ElGamal", "BC");

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);

        if (cipher.getOutputSize(in.length) != (size / 8) * 2)
        {
            fail("getOutputSize wrong on encryption");
        }

        byte[]  out = cipher.doFinal(in);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        if (cipher.getOutputSize(out.length) != (size / 8) - 1)
        {
            fail("getOutputSize wrong on decryption");
        }

        //
        // No Padding - maximum length
        //
        byte[]  modBytes = ((DHPublicKey)keyPair.getPublic()).getParams().getP().toByteArray();
        byte[]  maxInput = new byte[modBytes.length - 1];

        maxInput[0] |= 0x7f;

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);

        out = cipher.doFinal(maxInput);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        out = cipher.doFinal(out);

        if (!areEqual(out, maxInput))
        {
            fail("NoPadding test failed on decrypt expected " + new String(Hex.encode(maxInput)) + " got " + new String(Hex.encode(out)));
        }

        //
        // encrypt/decrypt
        //

        Cipher  c1 = Cipher.getInstance("ElGamal", "BC");
        Cipher  c2 = Cipher.getInstance("ElGamal", "BC");

        c1.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), rand);

        byte[]  out1 = c1.doFinal(in);

        c2.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[]  out2 = c2.doFinal(out1);

        if (!areEqual(in, out2))
        {
            fail(size + " encrypt test failed");
        }

        //
        // encrypt/decrypt with update
        //
        int outLen = c1.update(in, 0, 2, out1, 0);

        outLen += c1.doFinal(in, 2, in.length - 2, out1, outLen);

        out2 = new byte[c2.getOutputSize(out1.length)];

        outLen = c2.update(out1, 0, 2, out2, 0);

        outLen += c2.doFinal(out1, 2, out1.length - 2, out2, outLen);

        if (!areEqual(in, Arrays.copyOfRange(out2, 0, outLen)))
        {
            fail(size + " encrypt with update test failed");
        }

        //
        // public key encoding test
        //
        byte[]                  pubEnc = keyPair.getPublic().getEncoded();
        KeyFactory              keyFac = KeyFactory.getInstance("ElGamal", "BC");
        X509EncodedKeySpec      pubX509 = new X509EncodedKeySpec(pubEnc);
        DHPublicKey             pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
        DHParameterSpec         spec = pubKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit public key encoding/decoding test failed on parameters");
        }

        if (!((DHPublicKey)keyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key encoding/decoding test failed on y value");
        }

        //
        // public key serialisation test
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ObjectOutputStream      oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(keyPair.getPublic());

        ByteArrayInputStream   bIn = new ByteArrayInputStream(bOut.toByteArray());
        ObjectInputStream      oIn = new ObjectInputStream(bIn);

        pubKey = (DHPublicKey)oIn.readObject();
        spec = pubKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit public key serialisation test failed on parameters");
        }

        if (!((DHPublicKey)keyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key serialisation test failed on y value");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = keyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        DHPrivateKey        privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

        spec = privKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit private key encoding/decoding test failed on parameters");
        }

        if (!((DHPrivateKey)keyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key encoding/decoding test failed on y value");
        }

        //
        // private key serialisation test
        //
        bOut = new ByteArrayOutputStream();
        oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(keyPair.getPrivate());

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        oIn = new ObjectInputStream(bIn);

        privKey = (DHPrivateKey)oIn.readObject();
        spec = privKey.getParams();

        if (!spec.getG().equals(elParams.getG()) || !spec.getP().equals(elParams.getP()))
        {
            fail(size + " bit private key serialisation test failed on parameters");
        }

        if (!((DHPrivateKey)keyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key serialisation test failed on y value");
        }
    }

    public void testGetExceptionsPKCS1()
        throws Exception
    {
        SecureRandom rand = new SecureRandom();
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        keygen.initialize(new DHParameterSpec(p1024, g1024), rand);
        KeyPair keypair = keygen.genKeyPair();

        Cipher c = Cipher.getInstance("ELGAMAL/ECB/PKCS1Padding", "BC");
        byte[] ciphertext = new byte[1024 / 8];
        HashSet<String> exceptions = new HashSet<String>();
        final int SAMPLES = 1000;
        for (int i = 0; i < SAMPLES; i++)
        {
            rand.nextBytes(ciphertext);
            ciphertext[0] = (byte)0;
            try
            {
                c.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
                c.doFinal(ciphertext);
            }
            catch (Exception ex)
            {
                String message = ex.toString();
                exceptions.add(message);
            }
        }
        isTrue("exception count wrong", 1 == exceptions.size());
    }

    public void performTest()
        throws Exception
    {
        testDefault(64, g512, p512);

        testGP(512, 0, g512, p512);
        testGP(768, 0, g768, p768);
        testGP(1024, 0, g1024, p1024);

        testGP(512, 64, g512, p512);
        testGP(768, 128, g768, p768);
        testGP(1024, 256, g1024, p1024);

        testRandom(256);
        testGetExceptionsPKCS1();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ElGamalTest());
    }
}
