package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DHTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    // public key with mismatched oid/parameters
    private byte[] oldPubEnc = Base64.decode(
        "MIIBnzCCARQGByqGSM4+AgEwggEHAoGBAPxSrN417g43VAM9sZRf1dt6AocAf7D6" +
        "WVCtqEDcBJrMzt63+g+BNJzhXVtbZ9kp9vw8L/0PHgzv0Ot/kOLX7Khn+JalOECW" +
        "YlkyBhmOVbjR79TY5u2GAlvG6pqpizieQNBCEMlUuYuK1Iwseil6VoRuA13Zm7uw" +
        "WO1eZmaJtY7LAoGAQaPRCFKM5rEdkMrV9FNzeSsYRs8m3DqPnnJHpuySpyO9wUcX" +
        "OOJcJY5qvHbDO5SxHXu/+bMgXmVT6dXI5o0UeYqJR7fj6pR4E6T0FwG55RFr5Ok4" +
        "3C4cpXmaOu176SyWuoDqGs1RDGmYQjwbZUi23DjaaTFUly9LCYXMliKrQfEDgYQA" +
        "AoGAQUGCBN4TaBw1BpdBXdTvTfCU69XDB3eyU2FOBE3UWhpx9D8XJlx4f5DpA4Y6" +
        "6sQMuCbhfmjEph8W7/sbMurM/awR+PSR8tTY7jeQV0OkmAYdGK2nzh0ZSifMO1oE" +
        "NNhN2O62TLs67msxT28S4/S89+LMtc98mevQ2SX+JF3wEVU=");

    // bogus key with full PKCS parameter set
    private byte[] oldFullParams = Base64.decode(
        "MIIBIzCCARgGByqGSM4+AgEwggELAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9E" +
        "AMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f" +
        "6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv" +
        "8iIDGZ3RSAHHAoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9B4JnUVlX" +
        "jrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCjrh4rs6Z1kW6j" +
        "fwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQBTDv+z0kqAgFk" +
        "AwUAAgIH0A==");

    private byte[] samplePubEnc = Base64.decode(
       "MIIBpjCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I8" +
       "70QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWk" +
       "n5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HX" +
       "Ku/yIgMZndFIAccCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdR" +
       "WVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWR" +
       "bqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoC" +
       "AgIAA4GEAAKBgEIiqxoUW6E6GChoOgcfNbVFclW91ITf5MFSUGQwt2R0RHoOhxvO" +
       "lZhNs++d0VPATLAyXovjfgENT9SGCbuZttYcqqLdKTbMXBWPek+rfnAl9E4iEMED" +
       "IDd83FJTKs9hQcPAm7zmp0Xm1bGF9CbUFjP5G02265z7eBmHDaT0SNlB");

    private byte[] samplePrivEnc = Base64.decode(
       "MIIBZgIBADCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YR" +
       "t1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZ" +
       "UKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOu" +
       "K2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0H" +
       "gmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuz" +
       "pnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7P" +
       "SSoCAgIABEICQAZYXnBHazxXUUdFP4NIf2Ipu7du0suJPZQKKff81wymi2zfCfHh" +
       "uhe9gQ9xdm4GpzeNtrQ8/MzpTy+ZVrtd29Q=");

    public String getName()
    {
        return "DH";
    }

    private void testGP(
        String      algName,
        int         size,
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
        throws Exception
    {
        DHParameterSpec             dhParams = new DHParameterSpec(p, g, privateValueSize);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algName, "BC");

        keyGen.initialize(dhParams);

        testTwoParty(algName, size, privateValueSize, keyGen);

        KeyPair aKeyPair = keyGen.generateKeyPair();

        //
        // public key encoding test
        //
        byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(algName, "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
        DHPublicKey         pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
        DHParameterSpec     spec = pubKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit public key encoding/decoding test failed on parameters");
        }

        if (!((DHPublicKey)aKeyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key encoding/decoding test failed on y value");
        }

        //
        // public key serialisation test
        //
        pubKey = (DHPublicKey)serializeDeserialize(aKeyPair.getPublic());
        spec = pubKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit public key serialisation test failed on parameters");
        }

        if (!((DHPublicKey)aKeyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key serialisation test failed on y value");
        }

        if (!aKeyPair.getPublic().equals(pubKey))
        {
            fail("equals test failed");
        }

        if (aKeyPair.getPublic().hashCode() != pubKey.hashCode())
        {
            fail("hashCode test failed");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        DHPrivateKey        privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

        spec = privKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit private key encoding/decoding test failed on parameters");
        }

        if (!((DHPrivateKey)aKeyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key encoding/decoding test failed on y value");
        }

        //
        // private key serialisation test
        //
        privKey = (DHPrivateKey)serializeDeserialize(aKeyPair.getPrivate());
        spec = privKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit private key serialisation test failed on parameters");
        }

        if (!((DHPrivateKey)aKeyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key serialisation test failed on X value");
        }

        if (!aKeyPair.getPrivate().equals(privKey))
        {
            fail("equals test failed");
        }

        if (aKeyPair.getPrivate().hashCode() != privKey.hashCode())
        {
            fail("hashCode test failed");
        }

        if (!(privKey instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }

        //
        // three party test
        //
        KeyPairGenerator aPairGen = KeyPairGenerator.getInstance(algName, "BC");
        aPairGen.initialize(spec);
        KeyPair aPair = aPairGen.generateKeyPair();

        KeyPairGenerator bPairGen = KeyPairGenerator.getInstance(algName, "BC");
        bPairGen.initialize(spec);
        KeyPair bPair = bPairGen.generateKeyPair();

        KeyPairGenerator cPairGen = KeyPairGenerator.getInstance(algName, "BC");
        cPairGen.initialize(spec);
        KeyPair cPair = cPairGen.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance(algName, "BC");
        aKeyAgree.init(aPair.getPrivate());

        KeyAgreement bKeyAgree = KeyAgreement.getInstance(algName, "BC");
        bKeyAgree.init(bPair.getPrivate());

        KeyAgreement cKeyAgree = KeyAgreement.getInstance(algName, "BC");
        cKeyAgree.init(cPair.getPrivate());

        Key ac = aKeyAgree.doPhase(cPair.getPublic(), false);

        Key ba = bKeyAgree.doPhase(aPair.getPublic(), false);

        Key cb = cKeyAgree.doPhase(bPair.getPublic(), false);

        aKeyAgree.doPhase(cb, true);

        bKeyAgree.doPhase(ac, true);

        cKeyAgree.doPhase(ba, true);

        BigInteger aShared = new BigInteger(aKeyAgree.generateSecret());
        BigInteger bShared = new BigInteger(bKeyAgree.generateSecret());
        BigInteger cShared = new BigInteger(cKeyAgree.generateSecret());

        if (!aShared.equals(bShared))
        {
            fail(size + " bit 3-way test failed (a and b differ)");
        }

        if (!cShared.equals(bShared))
        {
            fail(size + " bit 3-way test failed (c and b differ)");
        }
    }

    private void testTwoParty(String algName, int size, int privateValueSize, KeyPairGenerator keyGen)
            throws Exception
    {
        testTwoParty(algName, size, privateValueSize, keyGen.generateKeyPair(), keyGen.generateKeyPair());
    }

    private byte[] testTwoParty(String algName, int size, int privateValueSize, KeyPair aKeyPair, KeyPair bKeyPair)
        throws Exception
    {
        //
        // a side
        //
        KeyAgreement aKeyAgree = KeyAgreement.getInstance(algName, "BC");

        checkKeySize(privateValueSize, aKeyPair);

        aKeyAgree.init(aKeyPair.getPrivate());

        //
        // b side
        //
        KeyAgreement bKeyAgree = KeyAgreement.getInstance(algName, "BC");

        checkKeySize(privateValueSize, bKeyPair);

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        byte[] aSecret = aKeyAgree.generateSecret();
        byte[] bSecret = bKeyAgree.generateSecret();

        if (!Arrays.areEqual(aSecret, bSecret))
        {
            fail(size + " bit 2-way test failed");
        }

        return aSecret;
    }

    private void testExplicitWrapping(
        int         size,
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
        throws Exception
    {
        DHParameterSpec             dhParams = new DHParameterSpec(p, g, privateValueSize);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        keyGen.initialize(dhParams);

        //
        // a side
        //
        KeyPair aKeyPair = keyGen.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");

        checkKeySize(privateValueSize, aKeyPair);

        aKeyAgree.init(aKeyPair.getPrivate());

        //
        // b side
        //
        KeyPair bKeyPair = keyGen.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");

        checkKeySize(privateValueSize, bKeyPair);

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        SecretKey k1 = aKeyAgree.generateSecret(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId());
        SecretKey k2 = bKeyAgree.generateSecret(PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId());
        
        // TODO Compare k1 and k2?
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
        AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("DH", "BC");
        a.init(size, new SecureRandom());
        AlgorithmParameters params = a.generateParameters();

        byte[] encodeParams = params.getEncoded();

        AlgorithmParameters a2 = AlgorithmParameters.getInstance("DH", "BC");
        a2.init(encodeParams);

        // a and a2 should be equivalent!
        byte[] encodeParams_2 = a2.getEncoded();

        if (!areEqual(encodeParams, encodeParams_2))
        {
            fail("encode/decode parameters failed");
        }

        DHParameterSpec dhP = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);

        testGP("DH", size, 0, dhP.getG(), dhP.getP());
    }

    private void testDefault(
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
        throws Exception
    {
        DHParameterSpec             dhParams = new DHParameterSpec(p, g, privateValueSize);
        String                      algName = "DH";
        int                         size = p.bitLength();

        new BouncyCastleProvider().setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, dhParams);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algName, "BC");

        keyGen.initialize(dhParams.getP().bitLength());

        testTwoParty("DH", size, privateValueSize, keyGen);

        KeyPair aKeyPair = keyGen.generateKeyPair();

        new BouncyCastleProvider().setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, null);

        //
        // public key encoding test
        //
        byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(algName, "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
        DHPublicKey         pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
        DHParameterSpec     spec = pubKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit public key encoding/decoding test failed on parameters");
        }

        if (!((DHPublicKey)aKeyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key encoding/decoding test failed on y value");
        }

        //
        // public key serialisation test
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ObjectOutputStream      oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(aKeyPair.getPublic());

        ByteArrayInputStream   bIn = new ByteArrayInputStream(bOut.toByteArray());
        ObjectInputStream      oIn = new ObjectInputStream(bIn);

        pubKey = (DHPublicKey)oIn.readObject();
        spec = pubKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit public key serialisation test failed on parameters");
        }

        if (!((DHPublicKey)aKeyPair.getPublic()).getY().equals(pubKey.getY()))
        {
            fail(size + " bit public key serialisation test failed on y value");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        DHPrivateKey        privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

        spec = privKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit private key encoding/decoding test failed on parameters");
        }

        if (!((DHPrivateKey)aKeyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key encoding/decoding test failed on y value");
        }

        //
        // private key serialisation test
        //
        bOut = new ByteArrayOutputStream();
        oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(aKeyPair.getPrivate());

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        oIn = new ObjectInputStream(bIn);

        privKey = (DHPrivateKey)oIn.readObject();
        spec = privKey.getParams();

        if (!spec.getG().equals(dhParams.getG()) || !spec.getP().equals(dhParams.getP()))
        {
            fail(size + " bit private key serialisation test failed on parameters");
        }

        if (!((DHPrivateKey)aKeyPair.getPrivate()).getX().equals(privKey.getX()))
        {
            fail(size + " bit private key serialisation test failed on y value");
        }

        //
        // three party test
        //
        KeyPairGenerator aPairGen = KeyPairGenerator.getInstance(algName, "BC");
        aPairGen.initialize(spec);
        KeyPair aPair = aPairGen.generateKeyPair();

        KeyPairGenerator bPairGen = KeyPairGenerator.getInstance(algName, "BC");
        bPairGen.initialize(spec);
        KeyPair bPair = bPairGen.generateKeyPair();

        KeyPairGenerator cPairGen = KeyPairGenerator.getInstance(algName, "BC");
        cPairGen.initialize(spec);
        KeyPair cPair = cPairGen.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance(algName, "BC");
        aKeyAgree.init(aPair.getPrivate());

        KeyAgreement bKeyAgree = KeyAgreement.getInstance(algName, "BC");
        bKeyAgree.init(bPair.getPrivate());

        KeyAgreement cKeyAgree = KeyAgreement.getInstance(algName, "BC");
        cKeyAgree.init(cPair.getPrivate());

        Key ac = aKeyAgree.doPhase(cPair.getPublic(), false);

        Key ba = bKeyAgree.doPhase(aPair.getPublic(), false);

        Key cb = cKeyAgree.doPhase(bPair.getPublic(), false);

        aKeyAgree.doPhase(cb, true);

        bKeyAgree.doPhase(ac, true);

        cKeyAgree.doPhase(ba, true);

        BigInteger aShared = new BigInteger(aKeyAgree.generateSecret());
        BigInteger bShared = new BigInteger(bKeyAgree.generateSecret());
        BigInteger cShared = new BigInteger(cKeyAgree.generateSecret());

        if (!aShared.equals(bShared))
        {
            fail(size + " bit 3-way test failed (a and b differ)");
        }

        if (!cShared.equals(bShared))
        {
            fail(size + " bit 3-way test failed (c and b differ)");
        }
    }

    private void testECDH(String algorithm, String cipher, int keyLen)
        throws Exception
    {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm, "BC");

        g.initialize(parameterSpec);

        //
        // a side
        //
        KeyPair aKeyPair = g.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance(algorithm, "BC");

        aKeyAgree.init(aKeyPair.getPrivate());

        //
        // b side
        //
        KeyPair bKeyPair = g.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance(algorithm, "BC");

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        SecretKey k1 = aKeyAgree.generateSecret(cipher);
        SecretKey k2 = bKeyAgree.generateSecret(cipher);

        if (!k1.equals(k2))
        {
            fail(algorithm + " 2-way test failed");
        }

        if (k1.getEncoded().length != keyLen / 8)
        {
            fail("key for " + cipher + " the wrong size expected " + keyLen / 8 + " got " + k1.getEncoded().length);
        }
    }

    private void testECDH(String algorithm)
        throws Exception
    {
        KeyPairGenerator    g = KeyPairGenerator.getInstance(algorithm, "BC");

        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                1); // h

        g.initialize(ecSpec, new SecureRandom());

        //
        // a side
        //
        KeyPair aKeyPair = g.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance(algorithm, "BC");

        aKeyAgree.init(aKeyPair.getPrivate());

        //
        // b side
        //
        KeyPair bKeyPair = g.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance(algorithm, "BC");

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
        BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

        if (!k1.equals(k2))
        {
            fail(algorithm + " 2-way test failed");
        }

        //
        // public key encoding test
        //
        byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(algorithm, "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
        ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

        if (!pubKey.getW().equals(((ECPublicKey)aKeyPair.getPublic()).getW()))
        {
            System.out.println(" expected " + pubKey.getW().getAffineX() + " got " + ((ECPublicKey)aKeyPair.getPublic()).getW().getAffineX());
            System.out.println(" expected " + pubKey.getW().getAffineY() + " got " + ((ECPublicKey)aKeyPair.getPublic()).getW().getAffineY());
            fail(algorithm + " public key encoding (W test) failed");
        }

        if (!pubKey.getParams().getGenerator().equals(((ECPublicKey)aKeyPair.getPublic()).getParams().getGenerator()))
        {
            fail(algorithm + " public key encoding (G test) failed");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

        if (!privKey.getS().equals(((ECPrivateKey)aKeyPair.getPrivate()).getS()))
        {
            fail(algorithm + " private key encoding (S test) failed");
        }

        if (!privKey.getParams().getGenerator().equals(((ECPrivateKey)aKeyPair.getPrivate()).getParams().getGenerator()))
        {
            fail(algorithm + " private key encoding (G test) failed");
        }
    }

    private void testExceptions()
    {
        try
        {
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");

            aKeyAgree.generateSecret("DES");
        }
        catch (IllegalStateException e)
        {
            // okay
        }
        catch (Exception e)
        {
            fail("Unexpected exception: " + e, e);
        }
    }

    private void testDESAndDESede(BigInteger g, BigInteger p)
        throws Exception
    {
        DHParameterSpec             dhParams = new DHParameterSpec(p, g, 256);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        keyGen.initialize(dhParams);

        KeyPair kp = keyGen.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");

        keyAgreement.init(kp.getPrivate());
        keyAgreement.doPhase(kp.getPublic(), true);

        SecretKey key = keyAgreement.generateSecret("DES");

        if (key.getEncoded().length != 8)
        {
            fail("DES length wrong");
        }

        if (!DESKeySpec.isParityAdjusted(key.getEncoded(), 0))
        {
            fail("DES parity wrong");
        }

        key = keyAgreement.generateSecret("DESEDE");

        if (key.getEncoded().length != 24)
        {
            fail("DESEDE length wrong");
        }

        if (!DESedeKeySpec.isParityAdjusted(key.getEncoded(), 0))
        {
            fail("DESEDE parity wrong");
        }

        key = keyAgreement.generateSecret("Blowfish");

        if (key.getEncoded().length != 16)
        {
            fail("Blowfish length wrong");
        }
    }

    private void testInitialise()
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        keyGen.initialize(512);

        keyGen.generateKeyPair();

        testTwoParty("DH", 512, 0, keyGen);
    }

    private void testSmallSecret()
        throws Exception
    {
        BigInteger p = new BigInteger("ff3b512a4cc0961fa625d6cbd9642c377ece46b8dbc3146a98e0567f944034b5e3a1406edb179a77cd2539bdb74dc819f0a74d486606e26e578ff52c5242a5ff", 16);
        BigInteger g = new BigInteger("58a66667431136e99d86de8199eb650a21afc9de3dd4ef9da6dfe89c866e928698952d95e68b418becef26f23211572eebfcbf328809bdaf02bba3d24c74f8c0", 16);

        DHPrivateKeySpec aPrivSpec = new DHPrivateKeySpec(
            new BigInteger("30a6ea4e2240a42867ad98bd3adbfd5b81aba48bd930f20a595983d807566f7cba4e766951efef2c6c0c1be3823f63d66e12c2a091d5ff3bbeb1ea6e335d072d", 16), p, g);
        DHPublicKeySpec aPubSpec = new DHPublicKeySpec(
                    new BigInteger("694dfea1bfc8897e2fcbfd88033ab34f4581892d7d5cc362dc056e3d43955accda12222bd651ca31c85f008a05dea914de68828dfd83a54a340fa84f3bbe6caf", 16), p, g);

        DHPrivateKeySpec bPrivSpec = new DHPrivateKeySpec(
                    new BigInteger("775b1e7e162190700e2212dd8e4aaacf8a2af92c9c108b81d5bf9a14548f494eaa86a6c4844b9512eb3e3f2f22ffec44c795c813edfea13f075b99bbdebb34bd", 16), p, g);

        DHPublicKeySpec bPubSpec = new DHPublicKeySpec(
                    new BigInteger("d8ddd4ff9246635eadbfa0bc2ef06d98a329b6e8cd2d1435d7b4921467570e697c9a9d3c172c684626a9d2b6b2fa0fc725d5b91f9a9625b717a4169bc714b064", 16), p, g);

        KeyFactory kFact = KeyFactory.getInstance("DH", "BC");

        byte[] secret = testTwoParty("DH", 512, 0, new KeyPair(kFact.generatePublic(aPubSpec), kFact.generatePrivate(aPrivSpec)), new KeyPair(kFact.generatePublic(bPubSpec), kFact.generatePrivate(bPrivSpec)));

        if (secret.length != ((p.bitLength() + 7) / 8))
        {
            fail("short secret wrong length");
        }

        if (!Arrays.areEqual(Hex.decode("00340d3309ddc86e99e2f0be4fc212837bfb5c59336b09b9e1aeb1884b72c8b485b56723d0bf1c1d37fc89a292fc1cface9125106f1df15f55f22e4f77c5879b"), secret))
        {
            fail("short secret mismatch");
        }
    }

    private void testEnc()
        throws Exception
    {
        KeyFactory  kFact = KeyFactory.getInstance("DH", "BC");

        Key k = kFact.generatePrivate(new PKCS8EncodedKeySpec(samplePrivEnc));

        if (!Arrays.areEqual(samplePrivEnc, k.getEncoded()))
        {
            fail("private key re-encode failed");
        }

        k = kFact.generatePublic(new X509EncodedKeySpec(samplePubEnc));

        if (!Arrays.areEqual(samplePubEnc, k.getEncoded()))
        {
            fail("public key re-encode failed");
        }

        k = kFact.generatePublic(new X509EncodedKeySpec(oldPubEnc));

        if (!Arrays.areEqual(oldPubEnc, k.getEncoded()))
        {
            fail("old public key re-encode failed");
        }

        k = kFact.generatePublic(new X509EncodedKeySpec(oldFullParams));

        if (!Arrays.areEqual(oldFullParams, k.getEncoded()))
        {
            fail("old full public key re-encode failed");
        }
    }

    private void testConfig()
    {
        ConfigurableProvider prov = new BouncyCastleProvider();

        DHParameterSpec dhSpec512 = new DHParameterSpec(
            new BigInteger("fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17", 16),
            new BigInteger("678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4", 16),
            384);

        DHParameterSpec dhSpec768 = new DHParameterSpec(
             new BigInteger("e9e642599d355f37c97ffd3567120b8e25c9cd43e927b3a9670fbec5d890141922d2c3b3ad2480093799869d1e846aab49fab0ad26d2ce6a22219d470bce7d777d4a21fbe9c270b57f607002f3cef8393694cf45ee3688c11a8c56ab127a3daf", 16),
             new BigInteger("30470ad5a005fb14ce2d9dcd87e38bc7d1b1c5facbaecbe95f190aa7a31d23c4dbbcbe06174544401a5b2c020965d8c2bd2171d3668445771f74ba084d2029d83c1c158547f3a9f1a2715be23d51ae4d3e5a1f6a7064f316933a346d3f529252", 16),
             384);

        DHParameterSpec dhSpec1024 = new DHParameterSpec(
                    new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a", 16),
                    new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7", 16),
                    512);

        prov.setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, dhSpec512);

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("config mismatch");
        }

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(768) != null)
        {
            fail("config found when none expected");
        }

        prov.setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, new DHParameterSpec[] { dhSpec512, dhSpec768, dhSpec1024 });

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("512 config mismatch");
        }

        if (!dhSpec768.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(768)))
        {
            fail("768 config mismatch");
        }

        if (!dhSpec1024.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(1024)))
        {
            fail("1024 config mismatch");
        }

        prov.setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, null);

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512) != null)
        {
            fail("config found for 512 when none expected");
        }

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(768) != null)
        {
            fail("config found for 768 when none expected");
        }

        prov.setParameter(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS, dhSpec512);

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("config mismatch");
        }

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(768) != null)
        {
            fail("config found when none expected");
        }

        prov.setParameter(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS, new DHParameterSpec[] { dhSpec512, dhSpec768, dhSpec1024 });

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("512 config mismatch");
        }

        if (!dhSpec768.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(768)))
        {
            fail("768 config mismatch");
        }

        if (!dhSpec1024.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(1024)))
        {
            fail("1024 config mismatch");
        }

        prov.setParameter(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS, null);

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512) != null)
        {
            fail("config found for 512 when none expected");
        }

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(768) != null)
        {
            fail("config found for 768 when none expected");
        }
    }

    public void performTest()
        throws Exception
    {
        testDefault(64, g512, p512);

        testEnc();
        testGP("DH", 512, 0, g512, p512);
        testGP("DiffieHellman", 768, 0, g768, p768);
        testGP("DIFFIEHELLMAN", 1024, 0, g1024, p1024);
        testGP("DH", 512, 64, g512, p512);
        testGP("DiffieHellman", 768, 128, g768, p768);
        testGP("DIFFIEHELLMAN", 1024, 256, g1024, p1024);
        testExplicitWrapping(512, 0, g512, p512);
        testRandom(256);

        testECDH("ECDH");
        testECDH("ECDHC");
        testECDH("ECDH", "AES", 256);
        testECDH("ECDH", "DESEDE", 192);
        testECDH("ECDH", "DES", 64);
        testECDH("ECDHwithSHA1KDF", "AES", 256);
        testECDH("ECDHwithSHA1KDF", "DESEDE", 192);

        testExceptions();
        testDESAndDESede(g768, p768);
        testInitialise();
        testSmallSecret();
        testConfig();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DHTest());
    }
}
