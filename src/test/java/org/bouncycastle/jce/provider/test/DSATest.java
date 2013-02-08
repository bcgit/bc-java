package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class DSATest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(new byte[][] { k1, k2 });
    
    private void testCompat()
        throws Exception
    {
        if (Security.getProvider("SUN") == null)
        {
            return;
        }

        Signature           s = Signature.getInstance("DSA", "SUN");
        KeyPairGenerator    g = KeyPairGenerator.getInstance("DSA", "SUN");
        byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
        
        g.initialize(512, new SecureRandom());
        
        KeyPair p = g.generateKeyPair();
        
        PrivateKey  sKey = p.getPrivate();
        PublicKey   vKey = p.getPublic();
        
        //
        // sign SUN - verify with BC 
        //
        s.initSign(sKey);
        
        s.update(data);
        
        byte[]  sigBytes = s.sign();
        
        s = Signature.getInstance("DSA", "BC");
        
        s.initVerify(vKey);
        
        s.update(data);
        
        if (!s.verify(sigBytes))
        {
            fail("SUN -> BC verification failed");
        }
        
        //
        // sign BC - verify with SUN
        //
        
        s.initSign(sKey);
        
        s.update(data);
        
        sigBytes = s.sign();
        
        s = Signature.getInstance("DSA", "SUN");
        
        s.initVerify(vKey);
        
        s.update(data);
        
        if (!s.verify(sigBytes))
        {
            fail("BC -> SUN verification failed");
        }

        //
        // key encoding test - BC decoding Sun keys
        //
        KeyFactory          f = KeyFactory.getInstance("DSA", "BC");
        X509EncodedKeySpec  x509s = new X509EncodedKeySpec(vKey.getEncoded());

        DSAPublicKey        k1 = (DSAPublicKey)f.generatePublic(x509s);

        checkPublic(k1, vKey);
        
        PKCS8EncodedKeySpec  pkcs8 = new PKCS8EncodedKeySpec(sKey.getEncoded());

        DSAPrivateKey        k2 = (DSAPrivateKey)f.generatePrivate(pkcs8);

        checkPrivateKey(k2, sKey);
        
        //
        // key decoding test - SUN decoding BC keys
        // 
        f = KeyFactory.getInstance("DSA", "SUN");
        x509s = new X509EncodedKeySpec(k1.getEncoded());
        
        vKey = (DSAPublicKey)f.generatePublic(x509s);

        checkPublic(k1, vKey);
        
        pkcs8 = new PKCS8EncodedKeySpec(k2.getEncoded());
        sKey = f.generatePrivate(pkcs8);

        checkPrivateKey(k2, sKey);
    }

    private void testNONEwithDSA()
        throws Exception
    {
        byte[] dummySha1 = Hex.decode("01020304050607080910111213141516");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DSA", "BC");

        kpGen.initialize(512);

        KeyPair          kp = kpGen.generateKeyPair();

        Signature        sig = Signature.getInstance("NONEwithDSA", "BC");

        sig.initSign(kp.getPrivate());

        sig.update(dummySha1);

        byte[] sigBytes = sig.sign();

        sig.initVerify(kp.getPublic());

        sig.update(dummySha1);

        sig.verify(sigBytes);

        // reset test

        sig.update(dummySha1);

        if (!sig.verify(sigBytes))
        {
            fail("NONEwithDSA failed to reset");
        }

        // lightweight test
        DSAPublicKey  key = (DSAPublicKey)kp.getPublic();
        DSAParameters params = new DSAParameters(key.getParams().getP(), key.getParams().getQ(), key.getParams().getG());
        DSAPublicKeyParameters keyParams = new DSAPublicKeyParameters(key.getY(), params);
        DSASigner signer = new DSASigner();
        ASN1Sequence derSig = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(sigBytes));

        signer.init(false, keyParams);

        if (!signer.verifySignature(dummySha1, DERInteger.getInstance(derSig.getObjectAt(0)).getValue(), DERInteger.getInstance(derSig.getObjectAt(1)).getValue()))
        {
            fail("NONEwithDSA not really NONE!");
        }
    }

    private void checkPublic(DSAPublicKey k1, PublicKey vKey)
    {
        if (!k1.getY().equals(((DSAPublicKey)vKey).getY()))
        {
            fail("public number not decoded properly");
        }

        if (!k1.getParams().getG().equals(((DSAPublicKey)vKey).getParams().getG()))
        {
            fail("public generator not decoded properly");
        }

        if (!k1.getParams().getP().equals(((DSAPublicKey)vKey).getParams().getP()))
        {
            fail("public p value not decoded properly");
        }

        if (!k1.getParams().getQ().equals(((DSAPublicKey)vKey).getParams().getQ()))
        {
            fail("public q value not decoded properly");
        }
    }

    private void checkPrivateKey(DSAPrivateKey k2, PrivateKey sKey)
    {
        if (!k2.getX().equals(((DSAPrivateKey)sKey).getX()))
        {
            fail("private number not decoded properly");
        }

        if (!k2.getParams().getG().equals(((DSAPrivateKey)sKey).getParams().getG()))
        {
            fail("private generator not decoded properly");
        }

        if (!k2.getParams().getP().equals(((DSAPrivateKey)sKey).getParams().getP()))
        {
            fail("private p value not decoded properly");
        }

        if (!k2.getParams().getQ().equals(((DSAPrivateKey)sKey).getParams().getQ()))
        {
            fail("private q value not decoded properly");
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

        ECCurve curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
        
        ECParameterSpec spec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
        
        
        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
                new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
                spec);
        
        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
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

    private void testNONEwithECDSA239bitPrime()
        throws Exception
    {
        ECCurve curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec spec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n


        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
                new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
                spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
                spec);

        Signature           sgr = Signature.getInstance("NONEwithECDSA", "BC");
        KeyFactory          f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey          sKey = f.generatePrivate(priKey);
        PublicKey           vKey = f.generatePublic(pubKey);

        byte[] message = "abc".getBytes();
        byte[] sig = Hex.decode("3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e64cb19604be06c57e761b3de5518f71de0f6e0cd2df677cec8a6ffcb690d");

        checkMessage(sgr, sKey, vKey, message, sig);

        message = "abcdefghijklmnopqrstuvwxyz".getBytes();
        sig = Hex.decode("3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e43fd65b3363d76aabef8630572257dbb67c82818ad9fad31256539b1b02c");

        checkMessage(sgr, sKey, vKey, message, sig);

        message = "a very very long message gauranteed to cause an overflow".getBytes();
        sig = Hex.decode("3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e7d5be84b22937a1691859a3c6fe45ed30b108574431d01b34025825ec17a");

        checkMessage(sgr, sKey, vKey, message, sig);
    }

    private void checkMessage(Signature sgr, PrivateKey sKey, PublicKey vKey, byte[] message, byte[] sig)
        throws InvalidKeyException, SignatureException
    {
        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

        SecureRandom    k = new FixedSecureRandom(kData);

        sgr.initSign(sKey, k);

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        if (!Arrays.areEqual(sigBytes, sig))
        {
            fail(new String(message) + " signature incorrect");
        }

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail(new String(message) + " verification failed");
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

        ECCurve curve = new ECCurve.F2m(
            239, // m
            36, // k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
    
        ECParameterSpec params = new ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
            BigInteger.valueOf(4)); // h
    
        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);
        
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
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

    private void testECDSA239bitBinary(String algorithm, DERObjectIdentifier oid)
        throws Exception
    {
//        BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
//        BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

        SecureRandom    k = new FixedSecureRandom(kData);

        ECCurve curve = new ECCurve.F2m(
            239, // m
            36, // k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b

        ECParameterSpec params = new ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
            BigInteger.valueOf(4)); // h

        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);

        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(
            curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
            params);

        Signature   sgr = Signature.getInstance(algorithm, "BC");
        KeyFactory  f = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey  sKey = f.generatePrivate(priKeySpec);
        PublicKey   vKey = f.generatePublic(pubKeySpec);
        byte[]      message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.initSign(sKey, k);

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr = Signature.getInstance(oid.getId(), "BC");

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("239 Bit EC RIPEMD160 verification failed");
        }
    }

    private void testGeneration()
        throws Exception
    {
        Signature           s = Signature.getInstance("DSA", "BC");
        KeyPairGenerator    g = KeyPairGenerator.getInstance("DSA", "BC");
        byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };


        // test exception
        //
        try
        {
            g.initialize(513, new SecureRandom());

            fail("illegal parameter 513 check failed.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            g.initialize(510, new SecureRandom());

            fail("illegal parameter 510 check failed.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            g.initialize(1025, new SecureRandom());

            fail("illegal parameter 1025 check failed.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        g.initialize(512, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        PrivateKey  sKey = p.getPrivate();
        PublicKey   vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        byte[]  sigBytes = s.sign();

        s = Signature.getInstance("DSA", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("DSA verification failed");
        }

        //
        // key decoding test - serialisation test
        //

        DSAPublicKey k1 = (DSAPublicKey)serializeDeserialize(vKey);

        checkPublic(k1, vKey);

        checkEquals(k1, vKey);

        DSAPrivateKey k2 = (DSAPrivateKey)serializeDeserialize(sKey);

        checkPrivateKey(k2, sKey);

        checkEquals(k2, sKey);

        if (!(k2 instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }

        //
        // ECDSA Fp generation test
        //
        s = Signature.getInstance("ECDSA", "BC");
        g = KeyPairGenerator.getInstance("ECDSA", "BC");

        ECCurve curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

        g.initialize(ecSpec, new SecureRandom());

        p = g.generateKeyPair();

        sKey = p.getPrivate();
        vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        sigBytes = s.sign();

        s = Signature.getInstance("ECDSA", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("ECDSA verification failed");
        }

        //
        // key decoding test - serialisation test
        //

        PublicKey eck1 = (PublicKey)serializeDeserialize(vKey);

        checkEquals(eck1, vKey);

        PrivateKey eck2 = (PrivateKey)serializeDeserialize(sKey);

        checkEquals(eck2, sKey);

        // Named curve parameter
        g.initialize(new ECNamedCurveGenParameterSpec("P-256"), new SecureRandom());

        p = g.generateKeyPair();

        sKey = p.getPrivate();
        vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        sigBytes = s.sign();

        s = Signature.getInstance("ECDSA", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("ECDSA verification failed");
        }

        //
        // key decoding test - serialisation test
        //

        eck1 = (PublicKey)serializeDeserialize(vKey);

        checkEquals(eck1, vKey);

        eck2 = (PrivateKey)serializeDeserialize(sKey);

        checkEquals(eck2, sKey);

        //
        // ECDSA F2m generation test
        //
        s = Signature.getInstance("ECDSA", "BC");
        g = KeyPairGenerator.getInstance("ECDSA", "BC");

        curve = new ECCurve.F2m(
                239, // m
                36, // k
                new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
                new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16)); // b
        
        ecSpec = new ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"), // n
            BigInteger.valueOf(4)); // h
        
        g.initialize(ecSpec, new SecureRandom());

        p = g.generateKeyPair();

        sKey = p.getPrivate();
        vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        sigBytes = s.sign();

        s = Signature.getInstance("ECDSA", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("ECDSA verification failed");
        }

        //
        // key decoding test - serialisation test
        //

        eck1 = (PublicKey)serializeDeserialize(vKey);

        checkEquals(eck1, vKey);

        eck2 = (PrivateKey)serializeDeserialize(sKey);

        checkEquals(eck2, sKey);

        if (!(eck2 instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }
    }

    private void checkEquals(Object o1, Object o2)
    {
        if (!o1.equals(o2))
        {
            fail("comparison test failed");
        }

        if (o1.hashCode() != o2.hashCode())
        {
            fail("hashCode test failed");
        }
    }
    
    private void testParameters()
        throws Exception
    {
        AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("DSA", "BC");
        a.init(512, random);
        AlgorithmParameters params = a.generateParameters();
        
        byte[] encodeParams = params.getEncoded();
        
        AlgorithmParameters a2 = AlgorithmParameters.getInstance("DSA", "BC");
        a2.init(encodeParams);
        
        // a and a2 should be equivalent!
        byte[] encodeParams_2 = a2.getEncoded();
        
        if (!areEqual(encodeParams, encodeParams_2))
        {
            fail("encode/decode parameters failed");
        }
        
        DSAParameterSpec dsaP = (DSAParameterSpec)params.getParameterSpec(DSAParameterSpec.class);
        
        KeyPairGenerator    g = KeyPairGenerator.getInstance("DSA", "BC");
        g.initialize(dsaP, new SecureRandom());
        KeyPair p = g.generateKeyPair();
        
        PrivateKey  sKey = p.getPrivate();
        PublicKey   vKey = p.getPublic();
        
        Signature           s = Signature.getInstance("DSA", "BC");
        byte[]              data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
        
        s.initSign(sKey);
        
        s.update(data);
        
        byte[]  sigBytes = s.sign();
        
        s = Signature.getInstance("DSA", "BC");
        
        s.initVerify(vKey);
        
        s.update(data);
        
        if (!s.verify(sigBytes))
        {
            fail("DSA verification failed");
        }
    }

    public void performTest()
        throws Exception
    {
        testCompat();
        testNONEwithDSA();
        testECDSA239bitPrime();
        testNONEwithECDSA239bitPrime();
        testECDSA239bitBinary();
        testECDSA239bitBinary("RIPEMD160withECDSA", TeleTrusTObjectIdentifiers.ecSignWithRipemd160);
        testECDSA239bitBinary("SHA1withECDSA", TeleTrusTObjectIdentifiers.ecSignWithSha1);
        testECDSA239bitBinary("SHA224withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        testECDSA239bitBinary("SHA256withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        testECDSA239bitBinary("SHA384withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        testECDSA239bitBinary("SHA512withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        testECDSA239bitBinary("SHA1withCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
        testECDSA239bitBinary("SHA224withCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
        testECDSA239bitBinary("SHA256withCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
        
        testGeneration();
        testParameters();
    }

    protected BigInteger[] derDecode(
        byte[]  encoding)
        throws IOException
    {
        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);
        ASN1Sequence            s = (ASN1Sequence)aIn.readObject();

        BigInteger[]            sig = new BigInteger[2];

        sig[0] = ((DERInteger)s.getObjectAt(0)).getValue();
        sig[1] = ((DERInteger)s.getObjectAt(1)).getValue();

        return sig;
    }

    public String getName()
    {
        return "DSA/ECDSA";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DSATest());
    }
}
