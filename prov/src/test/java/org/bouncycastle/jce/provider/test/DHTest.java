package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
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

    private BigInteger g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

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
        String algName,
        int size,
        int privateValueSize,
        BigInteger g,
        BigInteger p)
        throws Exception
    {
        DHParameterSpec dhParams = new DHParameterSpec(p, g, privateValueSize);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algName, "BC");

        keyGen.initialize(dhParams);

        testTwoParty(algName, size, privateValueSize, keyGen);

        KeyPair aKeyPair = keyGen.generateKeyPair();

        //
        // public key encoding test
        //
        byte[] pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory keyFac = KeyFactory.getInstance(algName, "BC");
        X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
        DHPublicKey pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
        DHParameterSpec spec = pubKey.getParams();

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
        byte[] privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        DHPrivateKey privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

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

        KeyAgreement noKdf = KeyAgreement.getInstance("DH", "BC");
        

        try
        {
            noKdf.init(aPair.getPrivate(), new UserKeyingMaterialSpec(new byte[20]));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("no KDF specified for UserKeyingMaterialSpec".equals(e.getMessage()));
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
        int size,
        int privateValueSize,
        BigInteger g,
        BigInteger p)
        throws Exception
    {
        DHParameterSpec dhParams = new DHParameterSpec(p, g, privateValueSize);

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
        int size)
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
        int privateValueSize,
        BigInteger g,
        BigInteger p)
        throws Exception
    {
        DHParameterSpec dhParams = new DHParameterSpec(p, g, privateValueSize);
        String algName = "DH";
        int size = p.bitLength();

        new BouncyCastleProvider().setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, dhParams);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algName, "BC");

        keyGen.initialize(dhParams.getP().bitLength());

        testTwoParty("DH", size, privateValueSize, keyGen);

        KeyPair aKeyPair = keyGen.generateKeyPair();

        new BouncyCastleProvider().setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, null);

        //
        // public key encoding test
        //
        byte[] pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory keyFac = KeyFactory.getInstance(algName, "BC");
        X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
        DHPublicKey pubKey = (DHPublicKey)keyFac.generatePublic(pubX509);
        DHParameterSpec spec = pubKey.getParams();

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
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(aKeyPair.getPublic());

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        ObjectInputStream oIn = new ObjectInputStream(bIn);

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
        byte[] privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        DHPrivateKey privKey = (DHPrivateKey)keyFac.generatePrivate(privPKCS8);

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

    private void testECDH(String algorithm, String curveName, String cipher, int keyLen)
        throws Exception
    {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
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
        SecretKey k2 = bKeyAgree.generateSecret(cipher + "[" + keyLen + "]");  // explicit key-len

        if (!k1.equals(k2))
        {
            fail(algorithm + " 2-way test failed");
        }

        if (k1.getEncoded().length != keyLen / 8)
        {
            fail("key for " + cipher + " the wrong size expected " + keyLen / 8 + " got " + k1.getEncoded().length);
        }
    }

    private void testECDH(String algorithm, String curveName, ASN1ObjectIdentifier algorithmOid, String cipher, int keyLen)
        throws Exception
    {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

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

        KeyAgreement bKeyAgree = KeyAgreement.getInstance(algorithmOid.getId(), "BC");

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        SecretKey k1 = aKeyAgree.generateSecret(cipher);
        SecretKey k2 = bKeyAgree.generateSecret(cipher + "[" + keyLen + "]");  // explicit key-len

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
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm, "BC");

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

        BigInteger k1 = new BigInteger(aKeyAgree.generateSecret());
        BigInteger k2 = new BigInteger(bKeyAgree.generateSecret());

        if (!k1.equals(k2))
        {
            fail(algorithm + " 2-way test failed");
        }

        //
        // public key encoding test
        //
        byte[] pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory keyFac = KeyFactory.getInstance(algorithm, "BC");
        X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(pubEnc);
        ECPublicKey pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

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
        byte[] privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        ECPrivateKey privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

        if (!privKey.getS().equals(((ECPrivateKey)aKeyPair.getPrivate()).getS()))
        {
            fail(algorithm + " private key encoding (S test) failed");
        }

        if (!privKey.getParams().getGenerator().equals(((ECPrivateKey)aKeyPair.getPrivate()).getParams().getGenerator()))
        {
            fail(algorithm + " private key encoding (G test) failed");
        }
    }

    private void testMinSpecValue()
        throws Exception
    {
        BigInteger p = new BigInteger("16560215747140417249215968347342080587", 16);
        BigInteger g = new BigInteger("1234567890", 16);

        DHParameterSpec serverParam = new DHParameterSpec(p, g);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

        try
        {
            keyGen.initialize(serverParam, new SecureRandom());
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("unsafe p value so small specific l required".equals(e.getMessage()));
        }

    }

    /*
     COUNT = 14
     XstatCAVS = 95fc47b3c755935a5babce2738d70557a43ded59c2ef8926a04e402cdb0c97b8
     YstatCAVS = 0b7faaefb56ea62937c2210c44feca95037d4cedfe01abd61cd8085ea195547e29aa2162951a73f9acf0f79de9da1ed587a1374d7b9c25a3ac4848a857edf28d4d6b80142871cd3fa984d673945a6ae69fbd0bc559a68330e7ba8556189216fe5d25abd8f1857baea7ab42fbdc3bb482272eca02fd0095c6b53c8d9ffb3ec172d97a3a1bde096178e2aaa3f084717f3e4530f58906f8f509533cead788b4efbb69ed78b91109965018b9a094612e60b1af470ec03565729c38e6d131eebac3483e7fdb24a7c85fd9bd362404956b928d6e1762b91b13825f7769b6e9426936c03f0328d9325f6fdd4af0b53ab1bc4201fedc5961c7f2c3a9668aa90ed2c4bb5d
     XephemCAVS = 6044f14699de46fe870688b27d5644a78da6e0758f2c999cc5e6d80a69220e2e
     YephemCAVS = 4a8d5a1a12cc0aeeb409e07dbffa052d289c4cb49d6550d8483fe063eee9d9faa4e918fe4daa858d535c4ed5cd270d96315db210e20b4446db4f460238b9187accc65b6d43e53b3c85eec3053c8bd675ef34dca5f6189f2233ecf0b1eda0995460ccdded4e31bf3170f9ec3941d010bbd1d7a0e017f0d43c0dd1d6435f8523babfa6599120f3cbf718e755cee86189459bcd20f52d2a0ca04bdff38e26197c211fcb64cc3d7d3f2f28ee4f7eb9dbdc84a420442b8481bfa3218f0d40c00abaedff682e7d66f6e891642bdea3e2d9c6240b768376abc50343cc69ab08b0a12cc4c6f1508444fd662c4825bd6da99eaab40ff5547aae539450062ce70b9722091b
     XstatIUT = 133a7729c7f1c1872438738edfa44d4cf44d3356d47b73b62eab45853ebdc66d
     YstatIUT = 21e25ee916b7b56a82f9e7622e909bef000997c44434e1149fa30cb1571500be5e61bab977d9ace85ba62a21719199b9a9747e3bcc0fa729a69c17f080633e6c1426db891721ae74b9752effe8a4b9749f8c7d8edd1f4356bab994304d3fde8223de38436a1a7ffb70371d25cf4c75df7f58cd833837318c1c2213f9a058655905d752fb637d3d7f780c3ee4a788120040424199bc99d96f3c3e56a2a9fe8d6d93e60a91b6f61a1cf0559bc68a1e33716a54fdbd2895c0d9d1f7da2cb936ff0c1bc7c60380d9cf4eaa8595366ed86a72cbd964d1e4309b2dd6efad1e944cdb92752ebe13d2e65772295fb13cd9f11d5b89253e4cc109b76d53306a6534be2641
     XephemIUT = 412a15e0866572a825219d3eaf9a4d6c0ed855180e5bdabc90f6d1a2354c3964
     YephemIUT = 8e235a5e20d0d1d431eb832a4309de239403a68217a595d30b2e7fd677ad5eb7a2a3cc5fb0793fe466169d8acac366a20de3863adc542a4fc6dd9dcb59126dfd0336b2c7736d26e87ad4fd84d6240e149f50ffcdaa81b60ca04a26f6335e1c41e49f183bf3a7a39ffe6bf2654874399e07d9a52fb34d08a7246929649171f6e7ceceb19016b83093a9a795245ae348346f9aa8f06380cb2b3cc9176e63e107734e23ead912e408c3085b6ba361cb66cf5b25ed03fdc6893646ea3cddd770fcb51d762a8f549b600044946c362f4dda85288fbc4499e022e2b705b4f1151d5206932da92b36c6b121e3a55a2edca4b42407021f4ea3f4748f21a36d722c086cf6
     CCMNonce = 7def4d439a9b7a6c5700bb9168
     OI = a1b2c3d4e543415653696412daed24199775845035176e67b0ace1b413e0
     CAVSTag = df851c60d5336269c68e42cc0d3b6ea5
     Z = 051f570adc0c2e26f946153f31784409102f5bd9edc2cdc466b14196b7489d2b157847fb7a13bfe89edc9712b2a161be360936802dc2c1158f0a84a2175671a4f46ed6fbadc4238244a217ed21a35e01b966b100daad49e2390e0c11525280b2ecc60ffad1e73ad12aa49e28fd9dfbf7d90ad75514c48a4c05f7bd8482929c68cc62e86424019462b1e2ef6a7a16507577ab144a89dafe57b9b0889d7afda25e62022f69220f0fb32046d0aa478bde5914177aeb4f359e790a6f9fac367f431b4e32acb8616f040c77cd99c1a666d4569c06b62faa4925f9c6f6525fe074cac972aead654c87dcc772b96992202afff62c82cc501b821bf0fd851942f0797dc98be4bdf193bc6d0d95d40146b5dad610bd4123413369686b460018918c493854a14558b302f6bc3d10109cbb549dc624448246e41a32842b1962a3b884b2eb8546f2bb51d30ceb80ae7a631f2f2fb820c7f149d5e53e2ec3d62f1ff5c6cb07f845de1b31be0e1d31143476a22952406c4fa37029b1e4d2107f5efb9df9e04ec2a4d9def274f934a0e34e22003f2142185c1f79d6058f612b1315acff738e94a18a08be36a3b327ae3e28e1c9aa96fe99cbe4fdeb0df92ff133e94929d6d50fad4d5bffe54454832125212c30dad53109e114413f954f02cfa39fcc0ef574074df2f1d6f4fcb9d99dfcbcc252ee42980f1a483508379434e1ef72358f39bb5725
     MacData = 4b435f325f56434156536964a1b2c3d4e54a8d5a1a12cc0aeeb409e07dbffa052d289c4cb49d6550d8483fe063eee9d9faa4e918fe4daa858d535c4ed5cd270d96315db210e20b4446db4f460238b9187accc65b6d43e53b3c85eec3053c8bd675ef34dca5f6189f2233ecf0b1eda0995460ccdded4e31bf3170f9ec3941d010bbd1d7a0e017f0d43c0dd1d6435f8523babfa6599120f3cbf718e755cee86189459bcd20f52d2a0ca04bdff38e26197c211fcb64cc3d7d3f2f28ee4f7eb9dbdc84a420442b8481bfa3218f0d40c00abaedff682e7d66f6e891642bdea3e2d9c6240b768376abc50343cc69ab08b0a12cc4c6f1508444fd662c4825bd6da99eaab40ff5547aae539450062ce70b9722091b8e235a5e20d0d1d431eb832a4309de239403a68217a595d30b2e7fd677ad5eb7a2a3cc5fb0793fe466169d8acac366a20de3863adc542a4fc6dd9dcb59126dfd0336b2c7736d26e87ad4fd84d6240e149f50ffcdaa81b60ca04a26f6335e1c41e49f183bf3a7a39ffe6bf2654874399e07d9a52fb34d08a7246929649171f6e7ceceb19016b83093a9a795245ae348346f9aa8f06380cb2b3cc9176e63e107734e23ead912e408c3085b6ba361cb66cf5b25ed03fdc6893646ea3cddd770fcb51d762a8f549b600044946c362f4dda85288fbc4499e022e2b705b4f1151d5206932da92b36c6b121e3a55a2edca4b42407021f4ea3f4748f21a36d722c086cf6
     DKM = 24a246e6cbaae19e4e8bffbe3167fbbc
     Result = P (10 - Z value should have leading 0 nibble )
     */
    private void testDHUnifiedTestVector1()
        throws Exception
    {
        // Test Vector from NIST sample data
        KeyFactory dhKeyFact = KeyFactory.getInstance("DH", "BC");

        DHParameterSpec dhSpec = new DHParameterSpec(
            new BigInteger("9a076bb269abfff57c72073053190a2008c3067fdcd9712ec00ee55c8fbf22af7c454dc5f10ae224d1e29fcccb3855a2509b082b934a353c21dfa5d1212f29d24866f022873d1f0b76373d47bb345e7e74f0ffc27e7c6c149282cb68a66705412995ed7a650a784f15107ed14244563b10f61d3f998b1466c9a3dd7c48a1b92d236b99b912a25f1c5279640c29714ce2123d222a6c9775223be80c5a4e9392db9ae45027110b75703c42d53fbfc1484e84cb70cabdcdcdc55066e5c03ce13ad0d7fa3af6f49101d454d5b3b77ce4c8db5772a427af7e351cdad3d7d278f52c3f57fc9274fc101c66d829871435ea2fc1f43f0e0d556a80dba9ab4e57c7b4b5a7", 16),
            // Q = fdd88b09ff0c6c6c334a598059c1b55396dab2de01af2e8d06481fd5cd506c71
            new BigInteger("167f9631c8aba192976a396b9df4bca5e54d1c1400eab4bdea27b1ca957211733d847026d2b3e3ea9b4c14d13b6e59f40c0df0c80bdecafb7ac414de2f920642c60d63406d2cc999ad149d24216b08a3952b50a50a088ab747de04bb4fd26899f7052970cfd0f65002cc0639bea634ba5ac2d98170b3a1b3ab5295e9395990b57fbdaf117662a9430da6b74d4e52d3969ce385b2fb61c11febd93867f1062084ca0a62c0de17b1e7265545198355e026818c037c43535de8f0d5cf0159501bcd35a4ba8fe92041a92e85fae03a051dfb3199d9764d17a3b8968eaf32e666ae867d1d0e6178ab31985b665e3178c36565e685046cb1d0611a25b0d559cd31f818", 16));

        KeyPair U1 = new KeyPair(
            dhKeyFact.generatePublic(new DHPublicKeySpec(
                new BigInteger("0b7faaefb56ea62937c2210c44feca95037d4cedfe01abd61cd8085ea195547e29aa2162951a73f9acf0f79de9da1ed587a1374d7b9c25a3ac4848a857edf28d4d6b80142871cd3fa984d673945a6ae69fbd0bc559a68330e7ba8556189216fe5d25abd8f1857baea7ab42fbdc3bb482272eca02fd0095c6b53c8d9ffb3ec172d97a3a1bde096178e2aaa3f084717f3e4530f58906f8f509533cead788b4efbb69ed78b91109965018b9a094612e60b1af470ec03565729c38e6d131eebac3483e7fdb24a7c85fd9bd362404956b928d6e1762b91b13825f7769b6e9426936c03f0328d9325f6fdd4af0b53ab1bc4201fedc5961c7f2c3a9668aa90ed2c4bb5d", 16),
                dhSpec.getP(), dhSpec.getG())),
            dhKeyFact.generatePrivate(new DHPrivateKeySpec(
                new BigInteger("95fc47b3c755935a5babce2738d70557a43ded59c2ef8926a04e402cdb0c97b8", 16),
                dhSpec.getP(), dhSpec.getG())));

        KeyPair U2 = new KeyPair(
            dhKeyFact.generatePublic(new DHPublicKeySpec(
                new BigInteger("4a8d5a1a12cc0aeeb409e07dbffa052d289c4cb49d6550d8483fe063eee9d9faa4e918fe4daa858d535c4ed5cd270d96315db210e20b4446db4f460238b9187accc65b6d43e53b3c85eec3053c8bd675ef34dca5f6189f2233ecf0b1eda0995460ccdded4e31bf3170f9ec3941d010bbd1d7a0e017f0d43c0dd1d6435f8523babfa6599120f3cbf718e755cee86189459bcd20f52d2a0ca04bdff38e26197c211fcb64cc3d7d3f2f28ee4f7eb9dbdc84a420442b8481bfa3218f0d40c00abaedff682e7d66f6e891642bdea3e2d9c6240b768376abc50343cc69ab08b0a12cc4c6f1508444fd662c4825bd6da99eaab40ff5547aae539450062ce70b9722091b", 16),
                dhSpec.getP(), dhSpec.getG())),
            dhKeyFact.generatePrivate(new DHPrivateKeySpec(
                new BigInteger("6044f14699de46fe870688b27d5644a78da6e0758f2c999cc5e6d80a69220e2e", 16),
                dhSpec.getP(), dhSpec.getG())));

        KeyPair V1 = new KeyPair(
            dhKeyFact.generatePublic(new DHPublicKeySpec(
                new BigInteger("21e25ee916b7b56a82f9e7622e909bef000997c44434e1149fa30cb1571500be5e61bab977d9ace85ba62a21719199b9a9747e3bcc0fa729a69c17f080633e6c1426db891721ae74b9752effe8a4b9749f8c7d8edd1f4356bab994304d3fde8223de38436a1a7ffb70371d25cf4c75df7f58cd833837318c1c2213f9a058655905d752fb637d3d7f780c3ee4a788120040424199bc99d96f3c3e56a2a9fe8d6d93e60a91b6f61a1cf0559bc68a1e33716a54fdbd2895c0d9d1f7da2cb936ff0c1bc7c60380d9cf4eaa8595366ed86a72cbd964d1e4309b2dd6efad1e944cdb92752ebe13d2e65772295fb13cd9f11d5b89253e4cc109b76d53306a6534be2641", 16),
                dhSpec.getP(), dhSpec.getG())),
            dhKeyFact.generatePrivate(new DHPrivateKeySpec(
                new BigInteger("133a7729c7f1c1872438738edfa44d4cf44d3356d47b73b62eab45853ebdc66d", 16),
                dhSpec.getP(), dhSpec.getG())));

        KeyPair V2 = new KeyPair(
            dhKeyFact.generatePublic(new DHPublicKeySpec(
                new BigInteger("8e235a5e20d0d1d431eb832a4309de239403a68217a595d30b2e7fd677ad5eb7a2a3cc5fb0793fe466169d8acac366a20de3863adc542a4fc6dd9dcb59126dfd0336b2c7736d26e87ad4fd84d6240e149f50ffcdaa81b60ca04a26f6335e1c41e49f183bf3a7a39ffe6bf2654874399e07d9a52fb34d08a7246929649171f6e7ceceb19016b83093a9a795245ae348346f9aa8f06380cb2b3cc9176e63e107734e23ead912e408c3085b6ba361cb66cf5b25ed03fdc6893646ea3cddd770fcb51d762a8f549b600044946c362f4dda85288fbc4499e022e2b705b4f1151d5206932da92b36c6b121e3a55a2edca4b42407021f4ea3f4748f21a36d722c086cf6", 16),
                dhSpec.getP(), dhSpec.getG())),
            dhKeyFact.generatePrivate(new DHPrivateKeySpec(
                new BigInteger("412a15e0866572a825219d3eaf9a4d6c0ed855180e5bdabc90f6d1a2354c3964", 16),
                dhSpec.getP(), dhSpec.getG())));

        byte[] x = calculateUnifiedAgreement("DHUwithSHA256CKDF", "AES[128]", U1, U2, V1, V2,
            Hex.decode("a1b2c3d4e543415653696412daed24199775845035176e67b0ace1b413e0"));

        if (x == null
            || !areEqual(Hex.decode("24a246e6cbaae19e4e8bffbe3167fbbc"), x))
        {
            fail("DH unified Test Vector #1 agreement failed, got: " + Hex.toHexString(x));
        }
    }

    private void testECUnifiedTestVector1()
        throws Exception
    {
        // Test Vector from NIST sample data

        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("P-224");
        KeyFactory ecKeyFact = KeyFactory.getInstance("EC", "BC");

        EllipticCurve ecCurve = new EllipticCurve(
            new ECFieldFp(namedSpec.getCurve().getField().getCharacteristic()),
            namedSpec.getCurve().getA().toBigInteger(), namedSpec.getCurve().getB().toBigInteger());
        ECParameterSpec ecSpec = new ECParameterSpec(ecCurve,
            new ECPoint(namedSpec.getG().getAffineXCoord().toBigInteger(), namedSpec.getG().getAffineYCoord().toBigInteger()),
            namedSpec.getN(), namedSpec.getH().intValue());
        
        KeyPair U1 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("040784e946ef1fae0cfe127042a310a018ba639d3f6b41f265904f0a7b21b7953efe638b45e6c0c0d34a883a510ce836d143d831daa9ce8a12")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("86d1735ca357890aeec8eccb4859275151356ecee9f1b2effb76b092", 16), ecSpec)));

        KeyPair U2 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("04b33713dc0d56215be26ee6c5e60ad36d12e02e78529ae3ff07873c6b39598bda41c1cf86ee3981f40e102333c15fef214bda034291c1aca6")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("764010b3137ef8d34a3552955ada572a4fa1bb1f5289f27c1bf18344", 16), ecSpec)));

        KeyPair V1 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("0484c22d9575d09e280613c8758467f84869c6eede4f6c1b644517d6a72c4fc5c68fa12b4c259032fc5949c630259948fca38fb3342d9cb0a8")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("e37964e391f5058fb43435352a9913438a1ec10831f755273285230a", 16), ecSpec)));

        KeyPair V2 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("044b917e9ce693b277c8095e535ea81c2dea089446a8c55438eda750fb6170c85b86390481fff2dff94b7dff3e42d35ff623921cb558967b48")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("ab40d67f59ba7265d8ad33ade8f704d13a7ba2298b69172a7cd02515", 16), ecSpec)));

        byte[] x = calculateUnifiedAgreement("ECCDHUwithSHA224CKDF", "AES[128]", U1, U2, V1, V2,
            Hex.decode("a1b2c3d4e54341565369643dba868da77897b6552f6f767ad873b232aa4a810a91863ec3dc86db53359a772dd76933"));

        if (x == null
            || !areEqual(Hex.decode("63b7ba5699927cb08e058b76af7fc0b0"), x))
        {
            fail("EC unified Test Vector #1 agreement failed, got: " + Hex.toHexString(x));
        }
    }

    private void testECUnifiedTestVector2()
        throws Exception
    {
        // Test Vector from NIST sample data

        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("P-256");
        KeyFactory ecKeyFact = KeyFactory.getInstance("EC", "BC");

        EllipticCurve ecCurve = new EllipticCurve(
            new ECFieldFp(namedSpec.getCurve().getField().getCharacteristic()),
            namedSpec.getCurve().getA().toBigInteger(), namedSpec.getCurve().getB().toBigInteger());
        ECParameterSpec ecSpec = new ECParameterSpec(ecCurve,
            new ECPoint(namedSpec.getG().getAffineXCoord().toBigInteger(), namedSpec.getG().getAffineYCoord().toBigInteger()),
            namedSpec.getN(), namedSpec.getH().intValue());

        KeyPair U1 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("047581b35964a983414ebdd56f4ebb1ddcad10881b200666a51ae41306e1ecf1db368468a5e8a65ca10ccea526472c8982db68316c468800e171c11f4ee694fce4")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("2eb7ef76d4936123b6f13035045aedf45c1c7731f35d529d25941926b5bb38bb", 16), ecSpec)));

        KeyPair U2 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("045b1e4cdeb0728333c0a51631b1a75269e4878d10732f4cb94d600483db4bd9ee625c374592c3db7e9f8b4f2c91a0098a158bc37b922e4243bd9cbdefe67d6ab0")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("78acde388a022261767e6b3dd6dd016c53b70a084260ec87d395aec761c082de", 16), ecSpec)));

        KeyPair V1 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("04e4916d616803ff1bd9569f35b7d06f792f19c1fb4e6fa916d686c027a17d8dffd570193d8e101624ac2ea0bcb762d5613f05452670f09af66ef70861fb528868")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("9c85898640a1b1de8ce7f557492dc1460530b9e17afaaf742eb953bb644e9c5a", 16), ecSpec)));

        KeyPair V2 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("04d1cd23c29d0fc865c316d44a1fd5adb6605ee47c9ddfec3a9b0a5e532d52704e74ff5d149aeb50856fefb38d5907b6dbb580fe6dc166bcfcbee4eb376d77e95c")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("d6e11d5d3b85b201b8f4c12dadfad3000e267961a806a0658a2b859d44389599", 16), ecSpec)));

        byte[] x = calculateUnifiedAgreement("ECCDHUwithSHA256CKDF", "AES[128]",
            U1, U2, V1, V2, Hex.decode("a1b2c3d4e54341565369649018558dc958160b4b1d240d06ea07c6f321a752496c1a3ff45cbb4b43507c6fe1997d1d"));

        if (x == null
            || !areEqual(Hex.decode("221d252072d6f85b8298eab6fc38634e"), x))
        {
            fail("EC unified Test Vector #2 agreement failed");
        }
    }

    private void testECUnifiedTestVector3()
        throws Exception
    {
        // Test Vector from NIST sample data - One pass unified.

        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("P-224");
        KeyFactory ecKeyFact = KeyFactory.getInstance("EC", "BC");

        EllipticCurve ecCurve = new EllipticCurve(
            new ECFieldFp(namedSpec.getCurve().getField().getCharacteristic()),
            namedSpec.getCurve().getA().toBigInteger(), namedSpec.getCurve().getB().toBigInteger());
        ECParameterSpec ecSpec = new ECParameterSpec(ecCurve,
            new ECPoint(namedSpec.getG().getAffineXCoord().toBigInteger(), namedSpec.getG().getAffineYCoord().toBigInteger()),
            namedSpec.getN(), namedSpec.getH().intValue());

        KeyPair U1 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("04030f136fa7fef90d185655ed1c6d46bacdb82001714e682cc80ca6b2d7c62e2f2e19d11755dba4aafd7e1ee5fda3e5f4d0af9a3ad773c38a")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("6fc464c741f52b2a2e4cde35673b87fdd0f52caf4e716230b11570ba", 16), ecSpec)));

        KeyPair V1 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("048f87f5f8a632c9a3348ea85b596c01c12ca29ca71583dcdc27ff9766351416a707b95fae67d56be5119b460a446b6a02db20a13bbc8ed13b")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("f5cb57a08a6949d3f2c2cc02e7c2252cecb3ebb8b3572943ceb407c7", 16), ecSpec)));

        KeyPair V2 = new KeyPair(
            ecKeyFact.generatePublic(new ECPublicKeySpec(
                ECPointUtil.decodePoint(ecCurve, Hex.decode("046fcc7d01f905b279e9413645d24cc30d293b98b0ea7bfe87124e4951eba04a74817f596a67c0bfe3b4f4cee99537a2ac1c6470dd006be8ca")), ecSpec)),
            ecKeyFact.generatePrivate(new ECPrivateKeySpec(
                new BigInteger("505b6f372725e293cda07bf0dd14dabe2faf0edaa5ab1c7d187a6138", 16), ecSpec)));

        byte[] x = calculateUnifiedAgreement("ECCDHUwithSHA224CKDF", "AES[128]", U1, U1, V1, V2,
            Hex.decode("a1b2c3d4e5434156536964b62d3197031c27af0e3b45228a8768efcc0b39a375f8f61852f8765b80c067eed4e4db30"));

        if (x == null
            || !areEqual(Hex.decode("0c96fa268b89cf664392621ad5e174a6"), x))
        {
            fail("EC unified Test Vector #3 agreement failed, got: " + Hex.toHexString(x));
        }
    }

    private byte[] calculateUnifiedAgreement(
        String alg,
        String keyAlg,
        KeyPair U1,
        KeyPair U2,
        KeyPair V1,
        KeyPair V2,
        byte[] oi)
        throws Exception
    {
        KeyAgreement u = KeyAgreement.getInstance(alg, "BC");

        u.init(U1.getPrivate(), new DHUParameterSpec(U2, V2.getPublic(), oi));

        u.doPhase(V1.getPublic(), true);

        SecretKey uk = u.generateSecret(keyAlg);
        byte[] ux = uk.getEncoded();

        KeyAgreement v = KeyAgreement.getInstance(alg, "BC");

        v.init(V1.getPrivate(), new DHUParameterSpec(V2, U2.getPublic(), oi));

        v.doPhase(U1.getPublic(), true);

        SecretKey vk = v.generateSecret(keyAlg);
        byte[] vx = vk.getEncoded();

        if (areEqual(ux, vx))
        {
            return ux;
        }

        return null;
    }

    private void testExceptions()
        throws Exception
    {
        try
        {
            KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");

            aKeyAgree.generateSecret("DES");
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            // okay
        }
        catch (Exception e)
        {
            fail("Unexpected exception: " + e, e);
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");

        keyGen.initialize(256);

        KeyPair kp = keyGen.generateKeyPair();
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH", "BC");

        agreement.init(kp.getPrivate());
        try
        {
            ECPoint fakePubPoint = new ECPoint(new BigInteger("12345"), new BigInteger("23457"));
            ECPublicKeySpec fakePubSpec = new ECPublicKeySpec(fakePubPoint, ((ECPublicKey)kp.getPublic()).getParams());
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            PublicKey fakePub = kf.generatePublic(fakePubSpec);
            agreement.doPhase(fakePub, true);

            fail("no exception on dud point");
        }
        catch (java.security.spec.InvalidKeySpecException e)
        {
            isTrue("wrong message: " + e.getMessage(), "invalid KeySpec: Point not on curve".equals(e.getMessage()));
        }
        catch (java.security.InvalidKeyException e)
        {
            isTrue("wrong message: " + e.getMessage(), "calculation failed: Invalid point".equals(e.getMessage()));
        }

        agreement = KeyAgreement.getInstance("ECDH", "BC");

        try
        {
            agreement.init(kp.getPrivate(), new UserKeyingMaterialSpec(new byte[20]));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("no KDF specified for UserKeyingMaterialSpec".equals(e.getMessage()));
        }
    }

    private void testDESAndDESede(BigInteger g, BigInteger p)
        throws Exception
    {
        DHParameterSpec dhParams = new DHParameterSpec(p, g, 256);

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
        KeyFactory kFact = KeyFactory.getInstance("DH", "BC");

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

        DHParameterSpec dhSpec640 = new DHParameterSpec(
            new BigInteger("c3d5a7f9a1cd7330099cebb60194f5176793a1cf13cd429f37bcbf1a7ddd53893ffdf1228af760c4a448e459d9cbab8302cc8cfc3368db01972108587c72a0f8b512ede0c99a3bef16cda0de529c8be7", 16),
            new BigInteger("c066a53c43a55e3474e20de07d14a574f6f1febe0b55e4c49bf72b0c712e02a51b03f379f485884bfd1f53819347b69401b9292196092a635320313ec6ee5ee5a5eac7ab9c57f2631a71452feeab3ef", 16),
            320);

        DHParameterSpec dhSpec1024 = new DHParameterSpec(
            new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7", 16),
            new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a", 16),
            512);

        prov.setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, dhSpec512);

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("config mismatch");
        }

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(640) != null)
        {
            fail("config found when none expected");
        }

        prov.setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, new DHParameterSpec[]{dhSpec512, dhSpec640, dhSpec1024});

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("512 config mismatch");
        }

        if (!dhSpec640.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(640)))
        {
            fail("640 config mismatch");
        }

        if (!dhSpec1024.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(1024)))
        {
            fail("1024 config mismatch");
        }

        prov.setParameter(ConfigurableProvider.DH_DEFAULT_PARAMS, null);
        
        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(640) != null)
        {
            fail("config found for 640 when none expected");
        }

        prov.setParameter(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS, dhSpec512);

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("config mismatch");
        }

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(640) != null)
        {
            fail("config found when none expected");
        }

        prov.setParameter(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS, new DHParameterSpec[]{dhSpec512, dhSpec640, dhSpec1024});

        if (!dhSpec512.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(512)))
        {
            fail("512 config mismatch");
        }

        if (!dhSpec640.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(640)))
        {
            fail("640 config mismatch");
        }

        if (!dhSpec1024.equals(BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(1024)))
        {
            fail("1024 config mismatch");
        }

        prov.setParameter(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS, null);

        if (BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(640) != null)
        {
            fail("config found for 640 when none expected");
        }
    }

    static final String MESSAGE = "Hello";

    static final String PROVIDER_NAME = "BC";
    static final SecureRandom rand = new SecureRandom();

    public void setUp()
    {
        // Add BouncyCastle for testing.
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("WARNING: Using BouncyCastleProvider");
    }

    public DHParameterSpec ike2048()
    {
        final BigInteger p = new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
                + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
                + "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
                + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
                + "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
                + "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
                + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
                + "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16);
        final BigInteger g = new BigInteger("2");
        return new DHParameterSpec(p, g);
    }

    /**
     * Tests whether a provider accepts invalid public keys that result in predictable shared secrets.
     * This test is based on RFC 2785, Section 4 and NIST SP 800-56A,
     * If an attacker can modify both public keys in an ephemeral-ephemeral key agreement scheme then
     * it may be possible to coerce both parties into computing the same predictable shared key.
     * <p/>
     * Note: the test is quite whimsical. If the prime p is not a safe prime then the provider itself
     * cannot prevent all small-subgroup attacks because of the missing parameter q in the
     * Diffie-Hellman parameters. Implementations must add additional countermeasures such as the ones
     * proposed in RFC 2785.
     */
    private void testSubgroupConfinement()
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        DHParameterSpec params = ike2048();
        final BigInteger p = params.getP();
        final BigInteger g = params.getG();
        keyGen.initialize(params);
        PrivateKey priv = keyGen.generateKeyPair().getPrivate();
        KeyAgreement ka = KeyAgreement.getInstance("DH", "BC");
        BigInteger[] weakPublicKeys = {
            BigInteger.ZERO, BigInteger.ONE, p.subtract(BigInteger.ONE), p,
            p.add(BigInteger.ONE), BigInteger.ONE.negate()};
        for (final BigInteger weakKey : weakPublicKeys)
        {
            DHPublicKeySpec weakSpec = new DHPublicKeySpec(weakKey, p, g);
            KeyFactory kf = KeyFactory.getInstance("DH", "BC");
            try
            {
                kf.generatePublic(weakSpec);
                fail("Generated weak public key");
            }
            catch (GeneralSecurityException ex)
            {
                isTrue("wrong message (generate)", "invalid DH public key".equals(ex.getMessage()));
            }
            ka.init(priv);
            try
            {
                ka.doPhase(new DHPublicKey()
                {
                    public BigInteger getY()
                    {
                        return weakKey;
                    }

                    public DHParameterSpec getParams()
                    {
                        return new DHParameterSpec(p, g);
                    }

                    public String getAlgorithm()
                    {
                        return null;
                    }

                    public String getFormat()
                    {
                        return null;
                    }

                    public byte[] getEncoded()
                    {
                        return new byte[0];
                    }
                }, true);
                fail("Generated secrets with weak public key");
            }
            catch (GeneralSecurityException ex)
            {
                isTrue("wrong message (doPhase)", "Invalid DH PublicKey".equals(ex.getMessage()));
            }
        }
    }

    private void testGenerateUsingStandardGroup()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH", "BC");
        DHDomainParameterSpec mySpec = new DHDomainParameterSpec(DHStandardGroups.rfc7919_ffdhe2048);
        kpGen.initialize(mySpec, new SecureRandom());
        KeyPair kp = kpGen.generateKeyPair();

        /* Obtain encoded keys */
        PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(kp.getPublic().getEncoded());
    }

    private KeyPair generateDHKeyPair()
        throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH", "BC");

        keyPairGen.initialize(2048);

        return keyPairGen.generateKeyPair();
    }

    private SecretKey mqvGenerateAESKey(
        PrivateKey aPriv, PublicKey aPubEph, PrivateKey aPrivEph, PublicKey bPub, PublicKey bPubEph, byte[] keyMaterial)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("MQVwithSHA256KDF", "BC");

        agreement.init(aPriv, new MQVParameterSpec(aPubEph, aPrivEph, bPubEph, keyMaterial));

        agreement.doPhase(bPub, true);

        return agreement.generateSecret("AES");
    }

    private void mqvTest()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // Generate the key pairs for party A and party B
        KeyPair aKpS = generateDHKeyPair();
        KeyPair aKpE = generateDHKeyPair();    // A's ephemeral pair
        KeyPair bKpS = generateDHKeyPair();
        KeyPair bKpE = generateDHKeyPair();    // B's ephemeral pair

        // key agreement generating an AES key
        byte[] keyMaterial = Strings.toByteArray("For an AES key");

        SecretKey aKey = mqvGenerateAESKey(
            aKpS.getPrivate(),
            aKpE.getPublic(), aKpE.getPrivate(),
            bKpS.getPublic(), bKpE.getPublic(), keyMaterial);
        SecretKey bKey = mqvGenerateAESKey(
            bKpS.getPrivate(),
            bKpE.getPublic(), bKpE.getPrivate(),
            aKpS.getPublic(), aKpE.getPublic(), keyMaterial);

        // compare the two return values.
        isTrue(Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));

        // check with encoding
        KeyFactory kFact = KeyFactory.getInstance("DH", "BC");

        aKey = mqvGenerateAESKey(
            kFact.generatePrivate(new PKCS8EncodedKeySpec(aKpS.getPrivate().getEncoded())),
            aKpE.getPublic(), aKpE.getPrivate(),
            bKpS.getPublic(), kFact.generatePublic(new X509EncodedKeySpec(bKpE.getPublic().getEncoded())), keyMaterial);
        bKey = mqvGenerateAESKey(
            bKpS.getPrivate(),
            bKpE.getPublic(), kFact.generatePrivate(new PKCS8EncodedKeySpec(bKpE.getPrivate().getEncoded())),
            aKpS.getPublic(), aKpE.getPublic(), keyMaterial);

        // compare the two return values.
        isTrue(Arrays.areEqual(aKey.getEncoded(), bKey.getEncoded()));
    }

    private void generalKeyTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        int[] keySizes = new int[]{512, 768, 1024, 2048};
        for (int i = 0; i != keySizes.length; i++)
        {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
            keyPairGenerator.initialize(keySizes[i], random);
            keyPairGenerator.generateKeyPair();
        }
    }

    public void performTest()
        throws Exception
    {
        generalKeyTest();
        testDefault(64, g512, p512);
        mqvTest();

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
        testECDH("ECDH", "secp521r1", "AES", 256);
        testECDH("ECDH", "secp521r1", "DESEDE", 192);
        testECDH("ECDH", "secp521r1", "DES", 64);
        testECDH("ECDHwithSHA1KDF", "secp521r1", "AES", 256);
        testECDH("ECDHwithSHA1KDF", "secp521r1", "DESEDE", 192);
        testECDH("ECDH", "Curve25519", "AES", 256);
        testECDH("ECDH", "Curve25519", "DESEDE", 192);
        testECDH("ECDH", "Curve25519", "DES", 64);
        testECDH("ECDHwithSHA1KDF", "Curve25519", "AES", 256);
        testECDH("ECKAEGWITHSHA1KDF", "secp256r1", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA1, "DESEDE", 192);
        testECDH("ECKAEGWITHSHA224KDF", "secp256r1", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA224, "DESEDE", 192);
        testECDH("ECKAEGWITHSHA256KDF", "secp256r1", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA256, "DESEDE", 192);
        testECDH("ECKAEGWITHSHA384KDF", "secp256r1", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA384,"AES", 256);
        testECDH("ECKAEGWITHSHA512KDF", "secp256r1", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA512,"DESEDE", 192);
        testECDH("ECKAEGWITHRIPEMD160KDF", "secp256r1", BSIObjectIdentifiers.ecka_eg_X963kdf_RIPEMD160, "AES", 256);

        testExceptions();
        testDESAndDESede(g768, p768);
        testInitialise();
        testSmallSecret();
        testConfig();
        testSubgroupConfinement();

        testECUnifiedTestVector1();
        testECUnifiedTestVector2();
        testECUnifiedTestVector3();

        testDHUnifiedTestVector1();

        testMinSpecValue();
        testGenerateUsingStandardGroup();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DHTest());
    }
}
