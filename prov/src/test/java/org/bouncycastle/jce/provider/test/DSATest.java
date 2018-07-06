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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
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
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.util.test.TestRandomData;

public class DSATest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(new byte[][] { k1, k2 });

    // DSA modified signatures, courtesy of the Google security team
    static final DSAPrivateKeySpec PRIVATE_KEY = new DSAPrivateKeySpec(
        // x
        new BigInteger(
            "15382583218386677486843706921635237927801862255437148328980464126979"),
        // p
        new BigInteger(
            "181118486631420055711787706248812146965913392568235070235446058914"
            + "1170708161715231951918020125044061516370042605439640379530343556"
            + "4101919053459832890139496933938670005799610981765220283775567361"
            + "4836626483403394052203488713085936276470766894079318754834062443"
            + "1033792580942743268186462355159813630244169054658542719322425431"
            + "4088256212718983105131138772434658820375111735710449331518776858"
            + "7867938758654181244292694091187568128410190746310049564097068770"
            + "8161261634790060655580211122402292101772553741704724263582994973"
            + "9109274666495826205002104010355456981211025738812433088757102520"
            + "562459649777989718122219159982614304359"),
        // q
        new BigInteger(
            "19689526866605154788513693571065914024068069442724893395618704484701"),
        // g
        new BigInteger(
            "2859278237642201956931085611015389087970918161297522023542900348"
            + "0877180630984239764282523693409675060100542360520959501692726128"
            + "3149190229583566074777557293475747419473934711587072321756053067"
            + "2532404847508798651915566434553729839971841903983916294692452760"
            + "2490198571084091890169933809199002313226100830607842692992570749"
            + "0504363602970812128803790973955960534785317485341020833424202774"
            + "0275688698461842637641566056165699733710043802697192696426360843"
            + "1736206792141319514001488556117408586108219135730880594044593648"
            + "9237302749293603778933701187571075920849848690861126195402696457"
            + "4111219599568903257472567764789616958430"));

    static final DSAPublicKeySpec PUBLIC_KEY = new DSAPublicKeySpec(
        new BigInteger(
            "3846308446317351758462473207111709291533523711306097971550086650"
            + "2577333637930103311673872185522385807498738696446063139653693222"
            + "3528823234976869516765207838304932337200968476150071617737755913"
            + "3181601169463467065599372409821150709457431511200322947508290005"
            + "1780020974429072640276810306302799924668893998032630777409440831"
            + "4314588994475223696460940116068336991199969153649625334724122468"
            + "7497038281983541563359385775312520539189474547346202842754393945"
            + "8755803223951078082197762886933401284142487322057236814878262166"
            + "5072306622943221607031324846468109901964841479558565694763440972"
            + "5447389416166053148132419345627682740529"),
         PRIVATE_KEY.getP(),
         PRIVATE_KEY.getQ(),
         PRIVATE_KEY.getG());

    // The following test vectors check for signature malleability and bugs. That means the test
    // vectors are derived from a valid signature by modifying the ASN encoding. A correct
    // implementation of DSA should only accept correct DER encoding and properly handle the others.
    // Allowing alternative BER encodings is in many cases benign. An example where this kind of
    // signature malleability was a problem: https://en.bitcoin.it/wiki/Transaction_Malleability
    static final String[] MODIFIED_SIGNATURES  = {
        "303e02811c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "303f0282001c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f"
        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
        "303e021d001e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd02811d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "303f021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd0282001d00ade65988d237d30f"
        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
        "303e021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021e0000ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "30813d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9e"
        + "f41dd424a4e1c8f16967cf3365813fe8786236",
        "3082003d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f"
        + "9ef41dd424a4e1c8f16967cf3365813fe8786236",
        "303d021c1e41b479ad576905b960fe14eadb91b0ccf34843dab916173bb8c9cd021d00ade65988d237d30f9ef4"
        + "1dd424a4e1c8f16967cf3365813fe87862360000",
        "3040021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca8021d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3040100",
        "303e021c57b10411b54ab248af03d8f2456676ebc6d3db5f1081492ac87e9ca802811d00942b117051d7d9d107fc42cac9c5a36a1fd7f0f8916ccca86cec4ed3"
    };

    private void testModified()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("DSA", "BC");
        PublicKey pubKey = kFact.generatePublic(PUBLIC_KEY);
        Signature sig = Signature.getInstance("DSA", "BC");

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

            isTrue("sig verified when shouldn't", failed);
        }
    }

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

    private void testNullParameters()
        throws Exception
    {
        KeyFactory f = KeyFactory.getInstance("DSA", "BC");
        X509EncodedKeySpec x509s = new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa), new ASN1Integer(10001)).getEncoded());

        DSAPublicKey key1 = (DSAPublicKey)f.generatePublic(x509s);
        DSAPublicKey key2 = (DSAPublicKey)f.generatePublic(x509s);

        isTrue("parameters not absent", key1.getParams() == null && key2.getParams() == null);
        isTrue("hashCode mismatch", key1.hashCode() == key2.hashCode());
        isTrue("not equal", key1.equals(key2));
        isTrue("encoding mismatch", Arrays.areEqual(x509s.getEncoded(), key1.getEncoded()));
    }

    private void testValidate()
        throws Exception
    {
        DSAParameterSpec dsaParams = new DSAParameterSpec(
            new BigInteger(
                        "F56C2A7D366E3EBDEAA1891FD2A0D099" +
                        "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" +
                        "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" +
                        "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" +
                        "5909132627F51A0C866877E672E555342BDF9355347DBD43" +
                        "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" +
                        "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" +
                        "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" +
                        "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" +
                        "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" +
                        "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16),
            new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16),
            new BigInteger(
                        "8DC6CC814CAE4A1C05A3E186A6FE27EA" +
                        "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" +
                        "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" +
                        "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" +
                        "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" +
                        "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" +
                        "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" +
                        "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" +
                        "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" +
                        "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" +
                        "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)
        );

        KeyFactory f = KeyFactory.getInstance("DSA", "BC");

        try
        {
            f.generatePublic(new DSAPublicKeySpec(BigInteger.valueOf(1), dsaParams.getP(), dsaParams.getG(), dsaParams.getQ()));

            fail("no exception");
        }
        catch (Exception e)
        {
            isTrue("mismatch", "invalid KeySpec: y value does not appear to be in correct group".equals(e.getMessage()));
        }
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

        if (!signer.verifySignature(dummySha1, ASN1Integer.getInstance(derSig.getObjectAt(0)).getValue(), ASN1Integer.getInstance(derSig.getObjectAt(1)).getValue()))
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

        SecureRandom k = new TestRandomBigInteger(kData);

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

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

    private void testNONEwithECDSA239bitPrime()
        throws Exception
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec spec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

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

    private void testECDSAP256sha3(ASN1ObjectIdentifier sigOid, int size, BigInteger s)
        throws Exception
    {
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        KeyFactory ecKeyFact = KeyFactory.getInstance("EC", "BC");

        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());

        ECCurve curve = p.getCurve();

        ECParameterSpec spec = new ECParameterSpec(
                curve,
                p.getG(), // G
                p.getN()); // n

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
                new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), // d
                spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            params.getCurve().decodePoint(Hex.decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), // Q
            spec);

        doEcDsaTest("SHA3-" + size + "withECDSA", s, ecKeyFact, pubKey, priKey);
        doEcDsaTest(sigOid.getId(), s, ecKeyFact, pubKey, priKey);
    }

    private void doEcDsaTest(String sigName, BigInteger s, KeyFactory ecKeyFact, ECPublicKeySpec pubKey, ECPrivateKeySpec priKey)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, SignatureException
    {
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335")));

        byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

        Signature dsa = Signature.getInstance(sigName, "BC");

        dsa.initSign(ecKeyFact.generatePrivate(priKey), k);

        dsa.update(M, 0, M.length);

        byte[] encSig = dsa.sign();

        ASN1Sequence sig = ASN1Sequence.getInstance(encSig);

        BigInteger r = new BigInteger("97354732615802252173078420023658453040116611318111190383344590814578738210384");

        BigInteger sigR = ASN1Integer.getInstance(sig.getObjectAt(0)).getValue();
        if (!r.equals(sigR))
        {
            fail("r component wrong." + Strings.lineSeparator()
                + " expecting: " + r.toString(16) + Strings.lineSeparator()
                + " got      : " + sigR.toString(16));
        }

        BigInteger sigS = ASN1Integer.getInstance(sig.getObjectAt(1)).getValue();
        if (!s.equals(sigS))
        {
            fail("s component wrong." + Strings.lineSeparator()
                + " expecting: " + s.toString(16) + Strings.lineSeparator()
                + " got      : " + sigS.toString(16));
        }

        // Verify the signature
        dsa.initVerify(ecKeyFact.generatePublic(pubKey));

        dsa.update(M, 0, M.length);

        if (!dsa.verify(encSig))
        {
            fail("signature fails");
        }
    }

    private void testDSAsha3(ASN1ObjectIdentifier sigOid, int size, BigInteger s)
        throws Exception
    {
        DSAParameterSpec dsaParams = new DSAParameterSpec(
            new BigInteger(
                        "F56C2A7D366E3EBDEAA1891FD2A0D099" +
                        "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" +
                        "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" +
                        "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" +
                        "5909132627F51A0C866877E672E555342BDF9355347DBD43" +
                        "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" +
                        "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" +
                        "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" +
                        "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" +
                        "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" +
                        "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16),
            new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16),
            new BigInteger(
                        "8DC6CC814CAE4A1C05A3E186A6FE27EA" +
                        "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" +
                        "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" +
                        "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" +
                        "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" +
                        "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" +
                        "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" +
                        "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" +
                        "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" +
                        "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" +
                        "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)
        );

        BigInteger x = new BigInteger("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C", 16);

        BigInteger y = new BigInteger(
                    "2828003D7C747199143C370FDD07A286" +
                    "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D" +
                    "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA" +
                    "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500" +
                    "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF" +
                    "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41" +
                    "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF" +
                    "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" +
                    "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" +
                    "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" +
                    "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16);

        DSAPrivateKeySpec priKey = new DSAPrivateKeySpec(
                x, dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

        DSAPublicKeySpec pubKey = new DSAPublicKeySpec(
            y, dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

        KeyFactory dsaKeyFact = KeyFactory.getInstance("DSA", "BC");

        doDsaTest("SHA3-" + size + "withDSA", s, dsaKeyFact, pubKey, priKey);
        doDsaTest(sigOid.getId(), s, dsaKeyFact, pubKey, priKey);
    }

    private void doDsaTest(String sigName, BigInteger s, KeyFactory ecKeyFact, DSAPublicKeySpec pubKey, DSAPrivateKeySpec priKey)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, SignatureException
    {
        SecureRandom k = new FixedSecureRandom(
            new FixedSecureRandom.Source[] { new FixedSecureRandom.BigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335"))),
                new FixedSecureRandom.Data(Hex.decode("01020304")) });

        byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

        Signature dsa = Signature.getInstance(sigName, "BC");

        dsa.initSign(ecKeyFact.generatePrivate(priKey), k);

        dsa.update(M, 0, M.length);

        byte[] encSig = dsa.sign();

        ASN1Sequence sig = ASN1Sequence.getInstance(encSig);

        BigInteger r = new BigInteger("4864074fe30e6601268ee663440e4d9b703f62673419864e91e9edb0338ce510", 16);

        BigInteger sigR = ASN1Integer.getInstance(sig.getObjectAt(0)).getValue();
        if (!r.equals(sigR))
        {
            fail("r component wrong." + Strings.lineSeparator()
                + " expecting: " + r.toString(16) + Strings.lineSeparator()
                + " got      : " + sigR.toString(16));
        }

        BigInteger sigS = ASN1Integer.getInstance(sig.getObjectAt(1)).getValue();
        if (!s.equals(sigS))
        {
            fail("s component wrong." + Strings.lineSeparator()
                + " expecting: " + s.toString(16) + Strings.lineSeparator()
                + " got      : " + sigS.toString(16));
        }

        // Verify the signature
        dsa.initVerify(ecKeyFact.generatePublic(pubKey));

        dsa.update(M, 0, M.length);

        if (!dsa.verify(encSig))
        {
            fail("signature fails");
        }
    }

    private void checkMessage(Signature sgr, PrivateKey sKey, PublicKey vKey, byte[] message, byte[] sig)
        throws InvalidKeyException, SignatureException
    {
        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

        SecureRandom    k = new TestRandomBigInteger(kData);

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

        SecureRandom k = new TestRandomBigInteger(kData);

        X9ECParameters x9 = ECNamedCurveTable.getByName("c2tnb239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec params = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

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

    private void testECDSA239bitBinary(String algorithm, ASN1ObjectIdentifier oid)
        throws Exception
    {
        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

        SecureRandom k = new TestRandomBigInteger(kData);

        X9ECParameters x9 = ECNamedCurveTable.getByName("c2tnb239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec params = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

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

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

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

        x9 = ECNamedCurveTable.getByName("c2tnb239v1");
        curve = x9.getCurve();
        ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

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

    private void testDSA2Parameters()
        throws Exception
    {
        byte[] seed = Hex.decode("4783081972865EA95D43318AB2EAF9C61A2FC7BBF1B772A09017BDF5A58F4FF0");

        AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("DSA", "BC");
        a.init(2048, new DSATestSecureRandom(seed));
        AlgorithmParameters params = a.generateParameters();

        DSAParameterSpec dsaP = (DSAParameterSpec)params.getParameterSpec(DSAParameterSpec.class);

        if (!dsaP.getQ().equals(new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16)))
        {
            fail("Q incorrect");
        }

        if (!dsaP.getP().equals(new BigInteger(
            "F56C2A7D366E3EBDEAA1891FD2A0D099" +
            "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" +
            "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" +
            "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" +
            "5909132627F51A0C866877E672E555342BDF9355347DBD43" +
            "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" +
            "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" +
            "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" +
            "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" +
            "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" +
            "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16)))
        {
            fail("P incorrect");
        }

        if (!dsaP.getG().equals(new BigInteger(
            "8DC6CC814CAE4A1C05A3E186A6FE27EA" +
            "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" +
            "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" +
            "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" +
            "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" +
            "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" +
            "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" +
            "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" +
            "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" +
            "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" +
            "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)))
        {
            fail("G incorrect");
        }

        KeyPairGenerator    g = KeyPairGenerator.getInstance("DSA", "BC");
        g.initialize(dsaP, new TestRandomBigInteger(Hex.decode("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C")));
        KeyPair p = g.generateKeyPair();

        DSAPrivateKey  sKey = (DSAPrivateKey)p.getPrivate();
        DSAPublicKey   vKey = (DSAPublicKey)p.getPublic();

        if (!vKey.getY().equals(new BigInteger(
            "2828003D7C747199143C370FDD07A286" +
            "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D" +
            "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA" +
            "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500" +
            "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF" +
            "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41" +
            "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF" +
            "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" +
            "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" +
            "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" +
            "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16)))
        {
            fail("Y value incorrect");
        }

        if (!sKey.getX().equals(
            new BigInteger("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C", 16)))
        {
            fail("X value incorrect");
        }

        byte[] encodeParams = params.getEncoded();

        AlgorithmParameters a2 = AlgorithmParameters.getInstance("DSA", "BC");
        a2.init(encodeParams);

        // a and a2 should be equivalent!
        byte[] encodeParams_2 = a2.getEncoded();

        if (!areEqual(encodeParams, encodeParams_2))
        {
            fail("encode/decode parameters failed");
        }

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

    private void testKeyGeneration(int keysize)
        throws Exception
    {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA", "BC");
        generator.initialize(keysize);
        KeyPair keyPair = generator.generateKeyPair();
        DSAPrivateKey priv = (DSAPrivateKey)keyPair.getPrivate();
        DSAParams params = priv.getParams();
        isTrue("keysize mismatch", keysize == params.getP().bitLength());
        // The NIST standard does not fully specify the size of q that
        // must be used for a given key size. Hence there are differences.
        // For example if keysize = 2048, then OpenSSL uses 256 bit q's by default,
        // but the SUN provider uses 224 bits. Both are acceptable sizes.
        // The tests below simply asserts that the size of q does not decrease the
        // overall security of the DSA.
        int qsize = params.getQ().bitLength();
        switch (keysize)
        {
        case 1024:
            isTrue("Invalid qsize for 1024 bit key:" + qsize, qsize >= 160);
            break;
        case 2048:
            isTrue("Invalid qsize for 2048 bit key:" + qsize, qsize >= 224);
            break;
        case 3072:
            isTrue("Invalid qsize for 3072 bit key:" + qsize, qsize >= 256);
            break;
        default:
            fail("Invalid key size:" + keysize);
        }
        // Check the length of the private key.
        // For example GPG4Browsers or the KJUR library derived from it use
        // q.bitCount() instead of q.bitLength() to determine the size of the private key
        // and hence would generate keys that are much too small.
        isTrue("privkey error", priv.getX().bitLength() >= qsize - 32);
    }

    private void testKeyGenerationAll()
        throws Exception
    {
        testKeyGeneration(1024);
        testKeyGeneration(2048);
        testKeyGeneration(3072);
    }

    public void performTest()
        throws Exception
    {
        testCompat();
        testNONEwithDSA();

        testDSAsha3(NISTObjectIdentifiers.id_dsa_with_sha3_224, 224, new BigInteger("613202af2a7f77e02b11b5c3a5311cf6b412192bc0032aac3ec127faebfc6bd0", 16));
        testDSAsha3(NISTObjectIdentifiers.id_dsa_with_sha3_256, 256, new BigInteger("2450755c5e15a691b121bc833b97864e34a61ee025ecec89289c949c1858091e", 16));
        testDSAsha3(NISTObjectIdentifiers.id_dsa_with_sha3_384, 384, new BigInteger("7aad97c0b71bb1e1a6483b6948a03bbe952e4780b0cee699a11731f90d84ddd1", 16));
        testDSAsha3(NISTObjectIdentifiers.id_dsa_with_sha3_512, 512, new BigInteger("725ad64d923c668e64e7c3898b5efde484cab49ce7f98c2885d2a13a9e355ad4", 16));

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
        testECDSA239bitBinary("SHA384withCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
        testECDSA239bitBinary("SHA512withCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);

        testECDSAP256sha3(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, 224, new BigInteger("84d7d8e68e405064109cd9fc3e3026d74d278aada14ce6b7a9dd0380c154dc94", 16));
        testECDSAP256sha3(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, 256, new BigInteger("99a43bdab4af989aaf2899079375642f2bae2dce05bcd8b72ec8c4a8d9a143f", 16));
        testECDSAP256sha3(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, 384, new BigInteger("aa27726509c37aaf601de6f7e01e11c19add99530c9848381c23365dc505b11a", 16));
        testECDSAP256sha3(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, 512, new BigInteger("f8306b57a1f5068bf12e53aabaae39e2658db39bc56747eaefb479995130ad16", 16));

        testGeneration();
        testParameters();
        testDSA2Parameters();
        testNullParameters();
        testValidate();
        testModified();
        testKeyGenerationAll();
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
        return "DSA/ECDSA";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DSATest());
    }

    private class DSATestSecureRandom
        extends TestRandomData
    {
        private boolean first = true;

        public DSATestSecureRandom(byte[] value)
        {
            super(value);
        }

       public void nextBytes(byte[] bytes)
       {
           if (first)
           {
               super.nextBytes(bytes);
               first = false;
           }
           else
           {
               bytes[bytes.length - 1] = 2;
           }
       }
    }
}
