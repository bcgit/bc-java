package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class ECDSA5Test
    extends SimpleTest
{
    private static final byte[] namedPubKey = Base64.decode(
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJMeqHZzm+saHt1m3a4u5BIqgSznd8LNvoeS93zzE9Ll31/AMaveAj" +
            "JqWxGdyCwnqmM5m3IFCZV3abKVGNpnuQwhIOPMm1355YX1JeEy/ifCx7lYe1o8Xs/Ajqz8cJB3j");

    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom random = new FixedSecureRandom(
        new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(k1), new FixedSecureRandom.Data(k2)});
    static final BigInteger PubX =
        new BigInteger("3390396496586153202365024500890309020181905168626402195853036609"
            + "0984128098564");
    static final BigInteger PubY =
        new BigInteger("1135421298983937257390683162600855221890652900790509030911087400"
            + "65052129055287");
    static final String[] VALID_SIGNATURES = {
        "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d49"
            + "1b39fd2c3f0220747291dd2f3f44af7ace68ea33431d6f94e418c106a6e76285"
            + "cd59f43260ecce",
    };

    // The following test vectors check for signature malleability and bugs. That means the test
    // vectors are derived from a valid signature by modifying the ASN encoding. A correct
    // implementation of ECDSA should only accept correct DER encoding and properly handle the
    // others (e.g. integer overflow, infinity, redundant parameters, etc). Allowing alternative BER
    // encodings is in many cases benign. An example where this kind of signature malleability was a
    // problem: https://en.bitcoin.it/wiki/Transaction_Malleability
    static final String[] MODIFIED_SIGNATURES = {
        "304602812100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f"
            + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "30470282002100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd"
            + "2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "304602220000b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f"
            + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f028120747291dd2f"
            + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f02820020747291dd"
            + "2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "3046022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f022100747291dd2f"
            + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "308145022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f"
            + "3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "30820045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd"
            + "2f3f44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce3000",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce1000",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000",
        "3045022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0000",
        "3048022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce058100",
        "3049022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce05820000",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce1100",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0500",
        "3047022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce2500",
        "3067022100b7babae9332b54b8a3a05b7004579821a887a1b21465f7db8a3d491b39fd2c3f0220747291dd2f3f"
            + "44af7ace68ea33431d6f94e418c106a6e76285cd59f43260ecce0220747291dd2f3f44af7ace68ea33431d6f"
            + "94e418c106a6e76285cd59f43260ecce"
    };

    private void testModified()
        throws Exception
    {
        ECNamedCurveParameterSpec namedCurve = ECNamedCurveTable.getParameterSpec("P-256");
        org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(namedCurve.getCurve().createPoint(PubX, PubY), namedCurve);
        KeyFactory kFact = KeyFactory.getInstance("EC", "BC");
        PublicKey pubKey = kFact.generatePublic(pubSpec);
        Signature sig = Signature.getInstance("SHA256WithECDSA", "BC");

        for (int i = 0; i != MODIFIED_SIGNATURES.length; i++)
        {
            sig.initVerify(pubKey);

            sig.update(Strings.toByteArray("Hello"));

            boolean failed;

            try
            {
                failed = !sig.verify(Hex.decode(MODIFIED_SIGNATURES[i]));
            }
            catch (SignatureException e)
            {
                failed = true;
            }

            isTrue("sig verified when shouldn't: " + i, failed);
        }
    }

    public void testNamedCurveInKeyFactory()
        throws Exception
    {
        KeyFactory kfBc = KeyFactory.getInstance("EC", "BC");
        BigInteger x = new BigInteger("24c7aa1d9ce6fac687b759b76b8bb9048aa04b39ddf0b36fa1e4bddf3cc4f4b977d7f00c6af7808c9a96c467720b09ea", 16);
        BigInteger y = new BigInteger("98ce66dc8142655dda6ca5463699ee43084838f326d77e79617d49784cbf89f0b1ee561ed68f17b3f023ab3f1c241de3", 16);
        String curveName = "secp384r1";
        ECPoint point = new ECPoint(x, y);

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "BC");
        parameters.init(new ECGenParameterSpec(curveName));
        ECParameterSpec ecParamSpec = parameters.getParameterSpec(ECParameterSpec.class);
        PublicKey pubKey = kfBc.generatePublic(new ECPublicKeySpec(point, ecParamSpec));

        isTrue(Arrays.areEqual(namedPubKey, pubKey.getEncoded()));
    }

    public void testKeyFactory()
        throws Exception
    {
        KeyFactory kfBc = KeyFactory.getInstance("EC", "BC");
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        
        kpGen.initialize(256);

        KeyPair kp = kpGen.generateKeyPair();

        isTrue(kfBc.getKeySpec(kp.getPublic(), KeySpec.class) instanceof ECPublicKeySpec);
        isTrue(kfBc.getKeySpec(kp.getPublic(), ECPublicKeySpec.class) instanceof ECPublicKeySpec);
        isTrue(kfBc.getKeySpec(kp.getPrivate(), KeySpec.class) instanceof ECPrivateKeySpec);
        isTrue(kfBc.getKeySpec(kp.getPrivate(), ECPrivateKeySpec.class) instanceof ECPrivateKeySpec);
    }

    private void pointCompressionTest()
        throws Exception
    {
        String[] ids = new String[]{
            "P-256",
            "B-409",
            "K-283"};

        for (int i = 0; i != ids.length; i++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

            kpGen.initialize(new ECGenParameterSpec(ids[i]));

            KeyPair kp = kpGen.generateKeyPair();

            byte[] enc1 = kp.getPublic().getEncoded();
            byte[] enc2 = org.bouncycastle.jcajce.util.ECKeyUtil.createKeyWithCompression((ECPublicKey)kp.getPublic()).getEncoded();

            isTrue(enc1.length >= enc2.length + 32);
        }
    }

    private void decodeTest()
    {
        EllipticCurve curve = new EllipticCurve(
            new ECFieldFp(new BigInteger("6277101735386680763835789423207666416083908700390324961279")), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)); // b

        ECPoint p = ECPointUtil.decodePoint(curve, Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"));

        if (!p.getAffineX().equals(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)))
        {
            fail("x uncompressed incorrectly");
        }

        if (!p.getAffineY().equals(new BigInteger("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)))
        {
            fail("y uncompressed incorrectly");
        }
    }

    /**
     * X9.62 - 1998,<br>
     * J.3.2, Page 155, ECDSA over the field Fp<br>
     * an example with 239 bit prime
     */
    private void testECDSA239bitPrime()
        throws Exception
    {
        BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
        BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

        SecureRandom k = new TestRandomBigInteger(kData);

        EllipticCurve curve = new EllipticCurve(
            new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
            1); // h


        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            ECPointUtil.decodePoint(curve, Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            spec);

        Signature sgr = Signature.getInstance("ECDSA", "BC");
        KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey sKey = f.generatePrivate(priKey);
        PublicKey vKey = f.generatePublic(pubKey);

        sgr.initSign(sKey, k);

        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        sgr.update(message);

        byte[] sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("239 Bit EC verification failed");
        }

        BigInteger[] sig = derDecode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + Strings.lineSeparator()
                + " expecting: " + r + Strings.lineSeparator()
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + Strings.lineSeparator()
                + " expecting: " + s + Strings.lineSeparator()
                + " got      : " + sig[1]);
        }
    }

    private void testSM2()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));

        KeyPair kp = kpGen.generateKeyPair();

        kpGen.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

        kp = kpGen.generateKeyPair();
    }

    private void testNonsense()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        try
        {
            kpGen.initialize(new ECGenParameterSpec("no_such_curve"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("unknown curve name: no_such_curve", e.getMessage());
        }
        KeyPair kp = kpGen.generateKeyPair();

        try
        {
            kpGen.initialize(new ECNamedCurveGenParameterSpec("1.2.3.4.5"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("unknown curve OID: 1.2.3.4.5", e.getMessage());
        }

        kp = kpGen.generateKeyPair();
    }

    // test BSI algorithm support.
    private void testBSI()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec(TeleTrusTObjectIdentifiers.brainpoolP512r1.getId()));

        KeyPair kp = kpGen.generateKeyPair();

        byte[] data = "Hello World!!!".getBytes();
        String[] cvcAlgs = {"SHA1WITHCVC-ECDSA", "SHA224WITHCVC-ECDSA",
            "SHA256WITHCVC-ECDSA", "SHA384WITHCVC-ECDSA",
            "SHA512WITHCVC-ECDSA"};
        String[] cvcOids = {EACObjectIdentifiers.id_TA_ECDSA_SHA_1.getId(), EACObjectIdentifiers.id_TA_ECDSA_SHA_224.getId(),
            EACObjectIdentifiers.id_TA_ECDSA_SHA_256.getId(), EACObjectIdentifiers.id_TA_ECDSA_SHA_384.getId(),
            EACObjectIdentifiers.id_TA_ECDSA_SHA_512.getId()};

        testBsiAlgorithms(kp, data, cvcAlgs, cvcOids);

        String[] plainAlgs = {"SHA1WITHPLAIN-ECDSA", "SHA224WITHPLAIN-ECDSA",
            "SHA256WITHPLAIN-ECDSA", "SHA384WITHPLAIN-ECDSA",
            "SHA512WITHPLAIN-ECDSA", "RIPEMD160WITHPLAIN-ECDSA"};
        String[] plainOids = {BSIObjectIdentifiers.ecdsa_plain_SHA1.getId(), BSIObjectIdentifiers.ecdsa_plain_SHA224.getId(),
            BSIObjectIdentifiers.ecdsa_plain_SHA256.getId(), BSIObjectIdentifiers.ecdsa_plain_SHA384.getId(),
            BSIObjectIdentifiers.ecdsa_plain_SHA512.getId(), BSIObjectIdentifiers.ecdsa_plain_RIPEMD160.getId()};

        testBsiAlgorithms(kp, data, plainAlgs, plainOids);

        kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec(SECObjectIdentifiers.secp521r1.getId()));

        kp = kpGen.generateKeyPair();

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(SECObjectIdentifiers.secp521r1.getId());
        testBsiSigSize(kp, spec.getN(), "SHA224WITHPLAIN-ECDSA");
    }

    private void testBsiAlgorithms(KeyPair kp, byte[] data, String[] algs, String[] oids)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {
        for (int i = 0; i != algs.length; i++)
        {
            Signature sig1 = Signature.getInstance(algs[i], "BC");
            Signature sig2 = Signature.getInstance(oids[i], "BC");

            sig1.initSign(kp.getPrivate());

            sig1.update(data);

            byte[] sig = sig1.sign();

            sig2.initVerify(kp.getPublic());

            sig2.update(data);

            if (!sig2.verify(sig))
            {
                fail("BSI CVC signature failed: " + algs[i]);
            }
        }
    }

    private void testBsiSigSize(KeyPair kp, BigInteger order, String alg)
        throws Exception
    {
        for (int i = 0; i != 20; i++)
        {
            Signature sig1 = Signature.getInstance(alg, "BC");
            Signature sig2 = Signature.getInstance(alg, "BC");

            sig1.initSign(kp.getPrivate());

            sig1.update(new byte[]{(byte)i});

            byte[] sig = sig1.sign();
            
            isTrue(sig.length == (2 * ((order.bitLength() + 7) / 8)));
            sig2.initVerify(kp.getPublic());

            sig2.update(new byte[]{(byte)i});

            if (!sig2.verify(sig))
            {
                fail("BSI CVC signature failed: " + alg);
            }
        }
    }
    
    /**
     * X9.62 - 1998,<br>
     * J.2.1, Page 100, ECDSA over the field F2m<br>
     * an example with 191 bit binary field
     */
    private void testECDSA239bitBinary()
        throws Exception
    {
        BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
        BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

        SecureRandom k = new TestRandomBigInteger(kData);

        EllipticCurve curve = new EllipticCurve(
            new ECFieldF2m(239, // m
                new int[]{36}), // k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b

        ECParameterSpec params = new ECParameterSpec(
            curve,
            ECPointUtil.decodePoint(curve, Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
            4); // h

        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
            ECPointUtil.decodePoint(curve, Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
            params);

        Signature sgr = Signature.getInstance("ECDSA", "BC");
        KeyFactory f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey sKey = f.generatePrivate(priKeySpec);
        PublicKey vKey = f.generatePublic(pubKeySpec);
        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        sgr.initSign(sKey, k);

        sgr.update(message);

        byte[] sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("239 Bit EC verification failed");
        }

        BigInteger[] sig = derDecode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + Strings.lineSeparator()
                + " expecting: " + r + Strings.lineSeparator()
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + Strings.lineSeparator()
                + " expecting: " + s + Strings.lineSeparator()
                + " got      : " + sig[1]);
        }
    }

    private void testGeneration()
        throws Exception
    {
        //
        // ECDSA generation test
        //
        byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
        Signature s = Signature.getInstance("ECDSA", "BC");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

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

        KeyPair p = g.generateKeyPair();

        PrivateKey sKey = p.getPrivate();
        PublicKey vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        byte[] sigBytes = s.sign();

        s = Signature.getInstance("ECDSA", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("ECDSA verification failed");
        }

        testKeyFactory((ECPublicKey)vKey, (ECPrivateKey)sKey);
        testSerialise((ECPublicKey)vKey, (ECPrivateKey)sKey);
    }

    private void testSerialise(ECPublicKey ecPublicKey, ECPrivateKey ecPrivateKey)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(ecPublicKey);
        oOut.writeObject(ecPrivateKey);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        PublicKey pubKey = (PublicKey)oIn.readObject();
        PrivateKey privKey = (PrivateKey)oIn.readObject();

        if (!ecPublicKey.equals(pubKey))
        {
            fail("public key serialisation check failed");
        }

        if (!ecPrivateKey.equals(privKey))
        {
            fail("private key serialisation check failed");
        }
    }

    private void testKeyFactory(ECPublicKey pub, ECPrivateKey priv)
        throws Exception
    {
        KeyFactory ecFact = KeyFactory.getInstance("ECDSA");

        ECPublicKeySpec pubSpec = (ECPublicKeySpec)ecFact.getKeySpec(pub, ECPublicKeySpec.class);
        ECPrivateKeySpec privSpec = (ECPrivateKeySpec)ecFact.getKeySpec(priv, ECPrivateKeySpec.class);

        if (!pubSpec.getW().equals(pub.getW()) || !pubSpec.getParams().getCurve().equals(pub.getParams().getCurve()))
        {
            fail("pubSpec not correct");
        }

        if (!privSpec.getS().equals(priv.getS()) || !privSpec.getParams().getCurve().equals(priv.getParams().getCurve()))
        {
            fail("privSpec not correct");
        }

        ECPublicKey pubKey = (ECPublicKey)ecFact.translateKey(pub);
        ECPrivateKey privKey = (ECPrivateKey)ecFact.translateKey(priv);

        if (!pubKey.getW().equals(pub.getW()) || !pubKey.getParams().getCurve().equals(pub.getParams().getCurve()))
        {
            fail("pubKey not correct");
        }

        if (!privKey.getS().equals(priv.getS()) || !privKey.getParams().getCurve().equals(priv.getParams().getCurve()))
        {
            fail("privKey not correct");
        }
    }

    private void testKeyConversion()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec("prime192v1"));

        KeyPair pair = kpGen.generateKeyPair();

        PublicKey pubKey = ECKeyUtil.publicToExplicitParameters(pair.getPublic(), "BC");

        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubKey.getEncoded()));
        X962Parameters params = X962Parameters.getInstance(info.getAlgorithm().getParameters());

        if (params.isNamedCurve() || params.isImplicitlyCA())
        {
            fail("public key conversion to explicit failed");
        }

        if (!((ECPublicKey)pair.getPublic()).getW().equals(((ECPublicKey)pubKey).getW()))
        {
            fail("public key conversion check failed");
        }

        PrivateKey privKey = ECKeyUtil.privateToExplicitParameters(pair.getPrivate(), "BC");
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privKey.getEncoded()));
        params = X962Parameters.getInstance(privInfo.getPrivateKeyAlgorithm().getParameters());

        if (params.isNamedCurve() || params.isImplicitlyCA())
        {
            fail("private key conversion to explicit failed");
        }

        if (!((ECPrivateKey)pair.getPrivate()).getS().equals(((ECPrivateKey)privKey).getS()))
        {
            fail("private key conversion check failed");
        }
    }

    private void testAdaptiveKeyConversion()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec("prime192v1"));

        KeyPair pair = kpGen.generateKeyPair();

        final PrivateKey privKey = pair.getPrivate();
        final PublicKey pubKey = pair.getPublic();

        Signature s = Signature.getInstance("ECDSA", "BC");

        // raw interface tests
        s.initSign(new PrivateKey()
        {
            public String getAlgorithm()
            {
                return privKey.getAlgorithm();
            }

            public String getFormat()
            {
                return privKey.getFormat();
            }

            public byte[] getEncoded()
            {
                return privKey.getEncoded();
            }
        });

        s.initVerify(new PublicKey()
        {
            public String getAlgorithm()
            {
                return pubKey.getAlgorithm();
            }

            public String getFormat()
            {
                return pubKey.getFormat();
            }

            public byte[] getEncoded()
            {
                return pubKey.getEncoded();
            }
        });


        s.initSign(new ECPrivateKey()
        {
            public String getAlgorithm()
            {
                return privKey.getAlgorithm();
            }

            public String getFormat()
            {
                return privKey.getFormat();
            }

            public byte[] getEncoded()
            {
                return privKey.getEncoded();
            }

            public BigInteger getS()
            {
                return ((ECPrivateKey)privKey).getS();
            }

            public ECParameterSpec getParams()
            {
                return ((ECPrivateKey)privKey).getParams();
            }
        });

        s.initVerify(new ECPublicKey()
        {
            public String getAlgorithm()
            {
                return pubKey.getAlgorithm();
            }

            public String getFormat()
            {
                return pubKey.getFormat();
            }

            public byte[] getEncoded()
            {
                return pubKey.getEncoded();
            }

            public ECPoint getW()
            {
                return ((ECPublicKey)pubKey).getW();
            }

            public ECParameterSpec getParams()
            {
                return ((ECPublicKey)pubKey).getParams();
            }
        });

        try
        {
            s.initSign(new PrivateKey()
            {
                public String getAlgorithm()
                {
                    return privKey.getAlgorithm();
                }

                public String getFormat()
                {
                    return privKey.getFormat();
                }

                public byte[] getEncoded()
                {
                    return null;
                }
            });

            fail("no exception thrown!!!");
        }
        catch (InvalidKeyException e)
        {
            // ignore
        }

        try
        {
            s.initVerify(new PublicKey()
            {
                public String getAlgorithm()
                {
                    return pubKey.getAlgorithm();
                }

                public String getFormat()
                {
                    return pubKey.getFormat();
                }

                public byte[] getEncoded()
                {
                    return null;
                }
            });

            fail("no exception thrown!!!");
        }
        catch (InvalidKeyException e)
        {
            // ignore
        }

        // try bogus encoding
        try
        {
            s.initSign(new PrivateKey()
            {
                public String getAlgorithm()
                {
                    return privKey.getAlgorithm();
                }

                public String getFormat()
                {
                    return privKey.getFormat();
                }

                public byte[] getEncoded()
                {
                    return new byte[20];
                }
            });

            fail("no exception thrown!!!");
        }
        catch (InvalidKeyException e)
        {
            // ignore
        }

        try
        {
            s.initVerify(new PublicKey()
            {
                public String getAlgorithm()
                {
                    return pubKey.getAlgorithm();
                }

                public String getFormat()
                {
                    return pubKey.getFormat();
                }

                public byte[] getEncoded()
                {
                    return new byte[20];
                }
            });

            fail("no exception thrown!!!");
        }
        catch (InvalidKeyException e)
        {
            // ignore
        }

        // try encoding of wrong key
        kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(512);

        pair = kpGen.generateKeyPair();

        final PrivateKey privRsa = pair.getPrivate();
        final PublicKey pubRsa = pair.getPublic();

        try
        {
            s.initSign(new PrivateKey()
            {
                public String getAlgorithm()
                {
                    return privRsa.getAlgorithm();
                }

                public String getFormat()
                {
                    return privRsa.getFormat();
                }

                public byte[] getEncoded()
                {
                    return privRsa.getEncoded();
                }
            });

            fail("no exception thrown!!!");

        }
        catch (InvalidKeyException e)
        {
            // ignore
        }

        try
        {
            s.initVerify(new PublicKey()
            {
                public String getAlgorithm()
                {
                    return pubRsa.getAlgorithm();
                }

                public String getFormat()
                {
                    return pubRsa.getFormat();
                }

                public byte[] getEncoded()
                {
                    return pubRsa.getEncoded();
                }
            });

            fail("no exception thrown!!!");
        }
        catch (InvalidKeyException e)
        {
            // ignore
        }
    }

    private void testAlgorithmParameters()
        throws Exception
    {
        AlgorithmParameters algParam = AlgorithmParameters.getInstance("EC", "BC");

        algParam.init(new ECGenParameterSpec("P-256"));

        byte[] encoded = algParam.getEncoded();

        algParam = AlgorithmParameters.getInstance("EC", "BC");

        algParam.init(encoded);

        ECGenParameterSpec genSpec = algParam.getParameterSpec(ECGenParameterSpec.class);

        if (!genSpec.getName().equals(X9ObjectIdentifiers.prime256v1.getId()))
        {
            fail("curve name not recovered");
        }

        ECParameterSpec ecSpec = algParam.getParameterSpec(ECParameterSpec.class);

        if (!ecSpec.getOrder().equals(NISTNamedCurves.getByName("P-256").getN()))
        {
            fail("incorrect spec recovered");
        }
    }

    private void testKeyPairGenerationWithOIDs()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec(X9ObjectIdentifiers.prime192v1.getId()));
        kpGen.initialize(new ECGenParameterSpec(TeleTrusTObjectIdentifiers.brainpoolP160r1.getId()));
        kpGen.initialize(new ECGenParameterSpec(SECObjectIdentifiers.secp128r1.getId()));

        try
        {
            kpGen.initialize(new ECGenParameterSpec("1.1"));

            fail("non-existant curve OID failed");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!"unknown curve OID: 1.1".equals(e.getMessage()))
            {
                fail("OID message check failed");
            }
        }

        try
        {
            kpGen.initialize(new ECGenParameterSpec("flibble"));

            fail("non-existant curve name failed");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            if (!"unknown curve name: flibble".equals(e.getMessage()))
            {
                fail("name message check failed");
            }
        }
    }

    private static class ECRandom
        extends SecureRandom
    {
        public void nextBytes(byte[] bytes)
        {
            byte[] src = new BigInteger("e2eb6663f551331bda00b90f1272c09d980260c1a70cab1ec481f6c937f34b62", 16).toByteArray();

            if (src.length <= bytes.length)
            {
                System.arraycopy(src, 0, bytes, bytes.length - src.length, src.length);
            }
            else
            {
                System.arraycopy(src, 0, bytes, 0, bytes.length);
            }
        }
    }

    private void testNamedCurveParameterPreservation()
        throws Exception
    {
        AlgorithmParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", "BC");
        keygen.initialize(ecSpec, new ECRandom());

        KeyPair keys = keygen.generateKeyPair();

        PrivateKeyInfo priv1 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
        SubjectPublicKeyInfo pub1 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());

        keygen = KeyPairGenerator.getInstance("EC", "BC");
        keygen.initialize(new ECGenParameterSpec("secp256r1"), new ECRandom());

        PrivateKeyInfo priv2 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
        SubjectPublicKeyInfo pub2 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());

        if (!priv1.equals(priv2) || !pub1.equals(pub2))
        {
            fail("mismatch between alg param spec and ECGenParameterSpec");
        }

        if (!(priv2.getPrivateKeyAlgorithm().getParameters() instanceof ASN1ObjectIdentifier))
        {
            fail("OID not preserved in private key");
        }

        if (!(pub1.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier))
        {
            fail("OID not preserved in public key");
        }
    }

    private void testNamedCurveSigning()
        throws Exception
    {
        testCustomNamedCurveSigning("secp256r1");

        try
        {
            testCustomNamedCurveSigning("secp256k1");
        }
        catch (IllegalArgumentException e)
        {
            if (!e.getMessage().equals("first coefficient is negative"))     // bogus jdk 1.5 exception...
            {
                throw e;
            }
        }
    }

    private void testCustomNamedCurveSigning(String name)
        throws Exception
    {
        X9ECParameters x9Params = ECUtil.getNamedCurveByOid(ECUtil.getNamedCurveOid(name));

        // TODO: one day this may have to change
        if (x9Params.getCurve() instanceof ECCurve.Fp)
        {
            fail("curve not custom curve!!");
        }

        AlgorithmParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", "BC");
        keygen.initialize(ecSpec, new ECRandom());

        KeyPair keys = keygen.generateKeyPair();

        PrivateKeyInfo priv1 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
        SubjectPublicKeyInfo pub1 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());

        keygen = KeyPairGenerator.getInstance("EC", "BC");
        keygen.initialize(new ECGenParameterSpec("secp256r1"), new ECRandom());

        Signature ecdsaSigner = Signature.getInstance("ECDSA", "BC");

        ecdsaSigner.initSign(keys.getPrivate());

        ecdsaSigner.update(new byte[100]);

        byte[] sig = ecdsaSigner.sign();

        ecdsaSigner.initVerify(keys.getPublic());

        ecdsaSigner.update(new byte[100]);

        if (!ecdsaSigner.verify(sig))
        {
            fail("signature failed to verify");
        }

        KeyFactory kFact = KeyFactory.getInstance("EC", "BC");

        PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(pub1.getEncoded()));
        PrivateKey pri = kFact.generatePrivate(new PKCS8EncodedKeySpec(priv1.getEncoded()));

        ecdsaSigner = Signature.getInstance("ECDSA", "BC");

        ecdsaSigner.initSign(pri);

        ecdsaSigner.update(new byte[100]);

        sig = ecdsaSigner.sign();

        ecdsaSigner.initVerify(pub);

        ecdsaSigner.update(new byte[100]);

        if (!ecdsaSigner.verify(sig))
        {
            fail("signature failed to verify");
        }
    }

    /**
     * COUNT = 1
     * dsCAVS = 00000179557decd75b797bea9db656ce99c03a6e0ab13804b5b589644f7db41ceba05c3940c300361061074ca72a828428d9198267fa0b75e1e3e785a0ff20e839414be0
     * QsCAVSx = 000001ce7da31681d5f176f3618f205969b9142520363dd26a596866c89988c932e3ce01904d12d1e9b105462e56163dbe7658ba3c472bf1f3c8165813295393ae346764
     * QsCAVSy = 000000e70d6e55b76ebd362ff071ab819315593cec650276209a9fdc2c1c48e03c35945f04e74d958cabd3f5e4d1f096a991e807a8f9d217de306a6b561038ca15aea4b9
     * NonceEphemCAVS = 4214a1a0a1d11679ae22f98d7ae483c1a74008a9cd7f7cf71b1f373a4226f5c58eb621ec56e2537797c01750dcbff07f613b9c58774f9af32aebeadd2226140dc7d56b1aa95c93ab1ec4412e2d0e42cdaac7bf9da3ddbf19fbb1edd0556d9c5a339808905fe8defd8b57ff8f34788192cc0cf7df17d1f351d69ac979a3a495931c287fb8
     * dsIUT = 000000c14895dfcc5a6b24994828cfd0a0cc0a881a70173a3eb05c57b098046c8e60a868f6176284aa346eff1fd1b8b879052c5a6d5fd0ae146b35ed7ecee32e294103cd
     * QsIUTx = 00000174a658695049db59f6bbe2ad23e1753bf58384a56fc9b3dec13eb873b33e1f4dbd24b6b4ca05a9a11ad531f6d99e9430a774980e8a8d9fd2d1e2a0d76fe3dd36c7
     * QsIUTy = 00000030639849e1df341973db44e7bbba5bb597884a439f9ce54620c3ca73a9804cc26fcda3aaf73ae5a11d5b325cae0e95cfafe1985c6c2fdb892722e7dd2c5d744cf3
     * deIUT = 00000138f54e986c7b44f49da389fa9f61bb7265f0cebdeddf09d47c72e55186e2520965fc2c31bb9c0a557e3c28e02a751f097e413c4252c7b0d22452d89f9ac314bc6e
     * QeIUTx = 000001b9fbce9c9ebb31070a4a4ac7af54ec9189c1f98948cd24ca0a5029217e4784d3c8692da08a6a512d1c9875d20d8e03664c148fa5d34bbac6d42e499ee5dbf01120
     * QeIUTy = 000000994a714b6d09afa896dbba9b4f436ab3cdb0d11dcd2aad28b7ba35d6fa6be537b6ffb0f9bf5fe1d594b8f8b8829687c9395c3d938c873f26c7100888c3aca2d59a
     * OI = a1b2c3d4e54341565369646dbb63a273c81e0aad02f92699bf7baa28fd4509145b0096746894e98e209a85ecb415b8
     * CAVSTag = 4ade5dc983cc1cf61c90fdbf726fa6a88e9bf411bbaf0015db06ff4348560e4d
     * Z = 019a19a0a99f60221ee23323b3317292e8c10d57ba04e0b33f6241979ec3895945eed0bdcbc59ab576e7047061f0d63d1aaf78b1d442028605aa1c0f963a3bc9d61a
     * MacData = 4b435f315f55a1b2c3d4e543415653696401b9fbce9c9ebb31070a4a4ac7af54ec9189c1f98948cd24ca0a5029217e4784d3c8692da08a6a512d1c9875d20d8e03664c148fa5d34bbac6d42e499ee5dbf0112000994a714b6d09afa896dbba9b4f436ab3cdb0d11dcd2aad28b7ba35d6fa6be537b6ffb0f9bf5fe1d594b8f8b8829687c9395c3d938c873f26c7100888c3aca2d59a4214a1a0a1d11679ae22f98d7ae483c1a74008a9cd7f7cf71b1f373a4226f5c58eb621ec56e2537797c01750dcbff07f613b9c58774f9af32aebeadd2226140dc7d56b1aa95c93ab1ec4412e2d0e42cdaac7bf9da3ddbf19fbb1edd0556d9c5a339808905fe8defd8b57ff8f34788192cc0cf7df17d1f351d69ac979a3a495931c287fb8
     * DKM = 0744e1774149a8b8f88d3a1e20ac1517efd2f54ba4b5f178de99f33b68eea426
     * Result = P (14 - DKM value should have leading 0 nibble )
     */
    public void testMQVwithHMACOnePass()
        throws Exception
    {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", "BC");

        algorithmParameters.init(new ECGenParameterSpec("P-521"));

        ECParameterSpec ecSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
        KeyFactory keyFact = KeyFactory.getInstance("EC", "BC");

        ECPrivateKey dsCAVS = (ECPrivateKey)keyFact.generatePrivate(new ECPrivateKeySpec(new BigInteger("00000179557decd75b797bea9db656ce99c03a6e0ab13804b5b589644f7db41ceba05c3940c300361061074ca72a828428d9198267fa0b75e1e3e785a0ff20e839414be0", 16), ecSpec));
        ECPublicKey qsCAVS = (ECPublicKey)keyFact.generatePublic(new ECPublicKeySpec(new ECPoint(
            new BigInteger("000001ce7da31681d5f176f3618f205969b9142520363dd26a596866c89988c932e3ce01904d12d1e9b105462e56163dbe7658ba3c472bf1f3c8165813295393ae346764", 16),
            new BigInteger("000000e70d6e55b76ebd362ff071ab819315593cec650276209a9fdc2c1c48e03c35945f04e74d958cabd3f5e4d1f096a991e807a8f9d217de306a6b561038ca15aea4b9", 16)), ecSpec));

        ECPrivateKey dsIUT = (ECPrivateKey)keyFact.generatePrivate(new ECPrivateKeySpec(new BigInteger("000000c14895dfcc5a6b24994828cfd0a0cc0a881a70173a3eb05c57b098046c8e60a868f6176284aa346eff1fd1b8b879052c5a6d5fd0ae146b35ed7ecee32e294103cd", 16), ecSpec));
        ECPublicKey qsIUT = (ECPublicKey)keyFact.generatePublic(new ECPublicKeySpec(new ECPoint(
            new BigInteger("00000174a658695049db59f6bbe2ad23e1753bf58384a56fc9b3dec13eb873b33e1f4dbd24b6b4ca05a9a11ad531f6d99e9430a774980e8a8d9fd2d1e2a0d76fe3dd36c7", 16),
            new BigInteger("00000030639849e1df341973db44e7bbba5bb597884a439f9ce54620c3ca73a9804cc26fcda3aaf73ae5a11d5b325cae0e95cfafe1985c6c2fdb892722e7dd2c5d744cf3", 16)), ecSpec));

        ECPrivateKey deIUT = (ECPrivateKey)keyFact.generatePrivate(new ECPrivateKeySpec(new BigInteger("00000138f54e986c7b44f49da389fa9f61bb7265f0cebdeddf09d47c72e55186e2520965fc2c31bb9c0a557e3c28e02a751f097e413c4252c7b0d22452d89f9ac314bc6e", 16), ecSpec));
        ECPublicKey qeIUT = (ECPublicKey)keyFact.generatePublic(new ECPublicKeySpec(new ECPoint(
            new BigInteger("000001b9fbce9c9ebb31070a4a4ac7af54ec9189c1f98948cd24ca0a5029217e4784d3c8692da08a6a512d1c9875d20d8e03664c148fa5d34bbac6d42e499ee5dbf01120", 16),
            new BigInteger("000000994a714b6d09afa896dbba9b4f436ab3cdb0d11dcd2aad28b7ba35d6fa6be537b6ffb0f9bf5fe1d594b8f8b8829687c9395c3d938c873f26c7100888c3aca2d59a", 16)), ecSpec));

        KeyAgreement uAgree = KeyAgreement.getInstance("ECMQVwithSHA512CKDF", "BC");

        uAgree.init(dsCAVS, new MQVParameterSpec(dsCAVS, qeIUT, Hex.decode("a1b2c3d4e54341565369646dbb63a273c81e0aad02f92699bf7baa28fd4509145b0096746894e98e209a85ecb415b8")));


        KeyAgreement vAgree = KeyAgreement.getInstance("ECMQVwithSHA512CKDF", "BC");
        vAgree.init(dsIUT, new MQVParameterSpec(deIUT, qsCAVS, Hex.decode("a1b2c3d4e54341565369646dbb63a273c81e0aad02f92699bf7baa28fd4509145b0096746894e98e209a85ecb415b8")));

        //
        // agreement
        //
        uAgree.doPhase(qsIUT, true);
        vAgree.doPhase(qsCAVS, true);

        byte[] ux = uAgree.generateSecret(PKCSObjectIdentifiers.id_hmacWithSHA512.getId()).getEncoded();
        byte[] vx = vAgree.generateSecret(PKCSObjectIdentifiers.id_hmacWithSHA512.getId()).getEncoded();

        if (!Arrays.areEqual(ux, vx))
        {
            fail("agreement values don't match");
        }

        if (!Arrays.areEqual(Hex.decode("0744e1774149a8b8f88d3a1e20ac1517efd2f54ba4b5f178de99f33b68eea426"), Arrays.copyOfRange(ux, 0, 32)))
        {
            fail("agreement values not correct");
        }
    }

    protected BigInteger[] derDecode(
        byte[] encoding)
        throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        ASN1Sequence s = (ASN1Sequence)aIn.readObject();

        BigInteger[] sig = new BigInteger[2];

        sig[0] = ((ASN1Integer)s.getObjectAt(0)).getValue();
        sig[1] = ((ASN1Integer)s.getObjectAt(1)).getValue();

        return sig;
    }

    public String getName()
    {
        return "ECDSA5";
    }

    public void performTest()
        throws Exception
    {
        testKeyConversion();
        testAdaptiveKeyConversion();
        decodeTest();
        testECDSA239bitPrime();
        testECDSA239bitBinary();
        testGeneration();
        testKeyPairGenerationWithOIDs();
        testNamedCurveParameterPreservation();
        testNamedCurveSigning();
        testBSI();
        testMQVwithHMACOnePass();
        testAlgorithmParameters();
        testModified();
        testSM2();
        testNonsense();
        testNamedCurveInKeyFactory();
        testKeyFactory();
        pointCompressionTest();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ECDSA5Test());
    }
}
