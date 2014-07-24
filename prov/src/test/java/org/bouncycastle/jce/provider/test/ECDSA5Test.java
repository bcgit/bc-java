package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class ECDSA5Test
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(new byte[][] { k1, k2 });
    
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

        SecureRandom    k = new FixedSecureRandom(kData);

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

        Signature           sgr = Signature.getInstance("ECDSA", "BC");
        KeyFactory          f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey          sKey = f.generatePrivate(priKey);
        PublicKey           vKey = f.generatePublic(pubKey);

        sgr.initSign(sKey, k);

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("239 Bit EC verification failed");
        }

        BigInteger[]  sig = derDecode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }
    }

    // test BSI algorithm support.
    private void testBSI()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        kpGen.initialize(new ECGenParameterSpec(TeleTrusTObjectIdentifiers.brainpoolP512r1.getId()));

        KeyPair kp = kpGen.generateKeyPair();

        byte[] data = "Hello World!!!".getBytes();
        String[] cvcAlgs = { "SHA1WITHCVC-ECDSA", "SHA224WITHCVC-ECDSA",
                             "SHA256WITHCVC-ECDSA", "SHA384WITHCVC-ECDSA",
                             "SHA512WITHCVC-ECDSA" };
        String[] cvcOids = { EACObjectIdentifiers.id_TA_ECDSA_SHA_1.getId(), EACObjectIdentifiers.id_TA_ECDSA_SHA_224.getId(),
                             EACObjectIdentifiers.id_TA_ECDSA_SHA_256.getId(), EACObjectIdentifiers.id_TA_ECDSA_SHA_384.getId(),
                             EACObjectIdentifiers.id_TA_ECDSA_SHA_512.getId() };

        testBsiAlgorithms(kp, data, cvcAlgs, cvcOids);

        String[] plainAlgs = { "SHA1WITHPLAIN-ECDSA", "SHA224WITHPLAIN-ECDSA",
                             "SHA256WITHPLAIN-ECDSA", "SHA384WITHPLAIN-ECDSA",
                             "SHA512WITHPLAIN-ECDSA", "RIPEMD160WITHPLAIN-ECDSA" };
        String[] plainOids = { BSIObjectIdentifiers.ecdsa_plain_SHA1.getId(), BSIObjectIdentifiers.ecdsa_plain_SHA224.getId(),
                                BSIObjectIdentifiers.ecdsa_plain_SHA256.getId(), BSIObjectIdentifiers.ecdsa_plain_SHA384.getId(),
                                BSIObjectIdentifiers.ecdsa_plain_SHA512.getId(), BSIObjectIdentifiers.ecdsa_plain_RIPEMD160.getId() };

        testBsiAlgorithms(kp, data, plainAlgs, plainOids);
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

        SecureRandom    k = new FixedSecureRandom(kData);

        EllipticCurve curve = new EllipticCurve(
            new ECFieldF2m(239, // m
                           new int[] { 36 }), // k
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
    
        Signature   sgr = Signature.getInstance("ECDSA", "BC");
        KeyFactory  f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey  sKey = f.generatePrivate(priKeySpec);
        PublicKey   vKey = f.generatePublic(pubKeySpec);
        byte[]      message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
       
        sgr.initSign(sKey, k);

        sgr.update(message);
        
        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("239 Bit EC verification failed");
        }

        BigInteger[]  sig = derDecode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong." + System.getProperty("line.separator")
                + " expecting: " + r + System.getProperty("line.separator")
                + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong." + System.getProperty("line.separator")
                + " expecting: " + s + System.getProperty("line.separator")
                + " got      : " + sig[1]);
        }
    }
    
    private void testGeneration()
        throws Exception
    {
        //
        // ECDSA generation test
        //
        byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
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
        PublicKey  vKey = p.getPublic();

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

        ECPublicKeySpec  pubSpec = (ECPublicKeySpec)ecFact.getKeySpec(pub, ECPublicKeySpec.class);
        ECPrivateKeySpec  privSpec = (ECPrivateKeySpec)ecFact.getKeySpec(priv, ECPrivateKeySpec.class);

        if (!pubSpec.getW().equals(pub.getW()) || !pubSpec.getParams().getCurve().equals(pub.getParams().getCurve()))
        {
            fail("pubSpec not correct");
        }

        if (!privSpec.getS().equals(priv.getS()) || !privSpec.getParams().getCurve().equals(priv.getParams().getCurve()))
        {
            fail("privSpec not correct");
        }

        ECPublicKey  pubKey = (ECPublicKey)ecFact.translateKey(pub);
        ECPrivateKey  privKey = (ECPrivateKey)ecFact.translateKey(priv);

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
        X962Parameters params = X962Parameters.getInstance(info.getAlgorithmId().getParameters());

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
        params = X962Parameters.getInstance(privInfo.getAlgorithmId().getParameters());

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
        final PublicKey  pubKey = pair.getPublic();

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
        final PublicKey  pubRsa = pair.getPublic();

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

    protected BigInteger[] derDecode(
        byte[]  encoding)
        throws IOException
    {
        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);
        ASN1Sequence            s = (ASN1Sequence)aIn.readObject();

        BigInteger[]            sig = new BigInteger[2];

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
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ECDSA5Test());
    }
}
