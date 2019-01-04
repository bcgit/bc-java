package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.GOST3410PrivateKey;
import org.bouncycastle.jce.interfaces.GOST3410PublicKey;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.x509.X509V3CertificateGenerator;

//import java.security.spec.ECGenParameterSpec;

public class GOST3410Test
    extends SimpleTest
{
    private static byte[] ecgostData = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    private static byte[] ecgost2012_256Key = Base64.decode("MGgwIQYIKoUDBwEBAQEwFQYJKoUDBwECAQEBBggqhQMHAQECAgNDAARAuSmiubNU4NMTvYsWb59uIa0dvNvikSyafTFTvHYhfoEeyVj5qeCoED1AjraW3Q44EZdNZaS5exAUIHuK5Bhd/Q==");
    private static byte[] ecgost2012_256Sig = Base64.decode("CNUdC6ny8sryzNcwGy7MG3DUbcU+3RgJNPWb3WVtAwUcbaFKPgL0TERfDM4Vsurwx0POt+PZCTxjaiaoY0UxkQ==");

    private static byte[] ecgost2012_512Key = Base64.decode("MIGqMCEGCCqFAwcBAQECMBUGCSqFAwcBAgECAQYIKoUDBwEBAgMDgYQABIGAhiwvUj3M58X6KQfFmqvQhka/JxigdS6hy6rqoYZec0pAwPKFNJ+AUl70zvNR/GDLB2DNBGryofKFXJk1l8aZCHM6cpuSzJbD7y728U/rclJ4GVDAbb4ktq4UmiYaJ7JZcc/CSL0qoj7w69sY7rWZm/T2o+hb1cM1jVq5/u5zYqo=");
    private static byte[] ecgost2012_512Sig = Base64.decode("uX4splTTDpH6T04tnElszTSmj+aTAl2LV7JxP+1xRRGoQ0ET2+QniOW+6WIOZzCZxEo75fZfx1jRHa7Eo99KfQNzHqmiN7G1Ch9pHQ7eMMwaLVurmWEFpZqBH4k5XfHTSPIa8mUmCn6808xMNy1VfwppbaJwRjtyW0h/CqeDTr8=");

    private void ecGOST3410Test()
        throws Exception
    {

        BigInteger r = new BigInteger("29700980915817952874371204983938256990422752107994319651632687982059210933395");
        BigInteger s = new BigInteger("46959264877825372965922731380059061821746083849389763294914877353246631700866");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("53854137677348463731403841147996619241504003434302020712960838528893196233395"));

        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041");
        BigInteger mod_q = new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619");

        ECCurve curve = new ECCurve.Fp(
            mod_p,
            new BigInteger("7"), // a
            new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414"), // b
            mod_q, ECConstants.ONE);

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(
                new BigInteger("2"), // x
                new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280")), // y
            mod_q, ECConstants.ONE);

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.createPoint(
                new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403"), // x
                new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994")), // y
            spec);

        Signature sgr = Signature.getInstance("ECGOST3410", "BC");
        KeyFactory f = KeyFactory.getInstance("ECGOST3410", "BC");
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
            fail("ECGOST3410 verification failed");
        }

        BigInteger[] sig = decode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1]);
        }
    }

    private void generationTest()
        throws Exception
    {
        Signature s = Signature.getInstance("GOST3410", "BC");
        KeyPairGenerator g = KeyPairGenerator.getInstance("GOST3410", "BC");
        byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
        GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId());

        g.initialize(gost3410P, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        PrivateKey sKey = p.getPrivate();
        PublicKey vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        byte[] sigBytes = s.sign();

        s = Signature.getInstance("GOST3410", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("GOST3410 verification failed");
        }

        //
        // default initialisation test
        //
        s = Signature.getInstance("GOST3410", "BC");
        g = KeyPairGenerator.getInstance("GOST3410", "BC");

        p = g.generateKeyPair();

        sKey = p.getPrivate();
        vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        sigBytes = s.sign();

        s = Signature.getInstance("GOST3410", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("GOST3410 verification failed");
        }

        //
        // encoded test
        //
        KeyFactory f = KeyFactory.getInstance("GOST3410", "BC");

        X509EncodedKeySpec x509s = new X509EncodedKeySpec(vKey.getEncoded());
        GOST3410PublicKey k1 = (GOST3410PublicKey)f.generatePublic(x509s);

        if (!k1.getY().equals(((GOST3410PublicKey)vKey).getY()))
        {
            fail("public number not decoded properly");
        }

        if (!k1.getParameters().equals(((GOST3410PublicKey)vKey).getParameters()))
        {
            fail("public parameters not decoded properly");
        }

        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(sKey.getEncoded());
        GOST3410PrivateKey k2 = (GOST3410PrivateKey)f.generatePrivate(pkcs8);

        if (!k2.getX().equals(((GOST3410PrivateKey)sKey).getX()))
        {
            fail("private number not decoded properly");
        }

        if (!k2.getParameters().equals(((GOST3410PrivateKey)sKey).getParameters()))
        {
            fail("private number not decoded properly");
        }

        k2 = (GOST3410PrivateKey)serializeDeserialize(sKey);
        if (!k2.getX().equals(((GOST3410PrivateKey)sKey).getX()))
        {
            fail("private number not deserialised properly");
        }

        if (!k2.getParameters().equals(((GOST3410PrivateKey)sKey).getParameters()))
        {
            fail("private number not deserialised properly");
        }

        checkEquals(k2, sKey);

        if (!(k2 instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }

        k1 = (GOST3410PublicKey)serializeDeserialize(vKey);

        if (!k1.getY().equals(((GOST3410PublicKey)vKey).getY()))
        {
            fail("public number not deserialised properly");
        }

        if (!k1.getParameters().equals(((GOST3410PublicKey)vKey).getParameters()))
        {
            fail("public parameters not deserialised properly");
        }

        checkEquals(k1, vKey);

        //
        // ECGOST3410 generation test
        //
        s = Signature.getInstance("ECGOST3410", "BC");
        g = KeyPairGenerator.getInstance("ECGOST3410", "BC");

//        BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p
//
//        ECCurve curve = new ECCurve.Fp(
//            mod_p, // p
//            new BigInteger("7"), // a
//            new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414")); // b
//
//        ECParameterSpec ecSpec = new ECParameterSpec(
//                curve,
//                    new ECPoint.Fp(curve,
//                                   new ECFieldElement.Fp(mod_p,new BigInteger("2")), // x
//                                   new ECFieldElement.Fp(mod_p,new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280"))), // y
//                    new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619")); // q

        g.initialize(new ECNamedCurveGenParameterSpec("GostR3410-2001-CryptoPro-A"), new SecureRandom());

        p = g.generateKeyPair();

        sKey = p.getPrivate();
        vKey = p.getPublic();

        s.initSign(sKey);

        s.update(data);

        sigBytes = s.sign();

        s = Signature.getInstance("ECGOST3410", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("ECGOST3410 verification failed");
        }

        //
        // encoded test
        //
        f = KeyFactory.getInstance("ECGOST3410", "BC");

        x509s = new X509EncodedKeySpec(vKey.getEncoded());
        ECPublicKey eck1 = (ECPublicKey)f.generatePublic(x509s);

        if (!eck1.getQ().equals(((ECPublicKey)vKey).getQ()))
        {
            fail("public number not decoded properly");
        }

        if (!eck1.getParameters().equals(((ECPublicKey)vKey).getParameters()))
        {
            fail("public parameters not decoded properly");
        }

        pkcs8 = new PKCS8EncodedKeySpec(sKey.getEncoded());
        ECPrivateKey eck2 = (ECPrivateKey)f.generatePrivate(pkcs8);

        if (!eck2.getD().equals(((ECPrivateKey)sKey).getD()))
        {
            fail("private number not decoded properly");
        }

        if (!eck2.getParameters().equals(((ECPrivateKey)sKey).getParameters()))
        {
            fail("private number not decoded properly");
        }

        eck2 = (ECPrivateKey)serializeDeserialize(sKey);
        if (!eck2.getD().equals(((ECPrivateKey)sKey).getD()))
        {
            fail("private number not decoded properly");
        }

        if (!eck2.getParameters().equals(((ECPrivateKey)sKey).getParameters()))
        {
            fail("private number not decoded properly");
        }

        checkEquals(eck2, sKey);

        if (!(eck2 instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }

        eck1 = (ECPublicKey)serializeDeserialize(vKey);

        if (!eck1.getQ().equals(((ECPublicKey)vKey).getQ()))
        {
            fail("public number not decoded properly");
        }

        if (!eck1.getParameters().equals(((ECPublicKey)vKey).getParameters()))
        {
            fail("public parameters not decoded properly");
        }

        checkEquals(eck1, vKey);
    }


    private void ecGOST34102012256Test()
        throws Exception
    {

        BigInteger r = new BigInteger("29700980915817952874371204983938256990422752107994319651632687982059210933395");
        BigInteger s = new BigInteger("574973400270084654178925310019147038455227042649098563933718999175515839552");

        BigInteger e = new BigInteger("20798893674476452017134061561508270130637142515379653289952617252661468872421");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("53854137677348463731403841147996619241504003434302020712960838528893196233395"));
        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041");
        BigInteger mod_q = new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619");

        ECCurve curve = new ECCurve.Fp(
            mod_p,
            new BigInteger("7"), // a
            new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414"), // b
            mod_q, ECConstants.ONE);

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(
                new BigInteger("2"), // x
                new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280")), // y
            mod_q, ECConstants.ONE);

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.createPoint(
                new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403"), // x
                new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994")), // y
            spec);

        KeyFactory f = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PrivateKey sKey = f.generatePrivate(priKey);
        PublicKey vKey = f.generatePublic(pubKey);

        ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
        CipherParameters param = ECUtil.generatePrivateKeyParameter(sKey);

        signer.init(true, new ParametersWithRandom(param, k));

        byte[] rev = e.toByteArray();
        byte[] message = new byte[rev.length];
        for (int i = 0; i != rev.length; i++)
        {
            message[i] = rev[rev.length - 1 - i];
        }
        BigInteger[] sig = signer.generateSignature(message);

        ECPublicKey ecPublicKey = (ECPublicKey)vKey;
        param = new ECPublicKeyParameters(
            ecPublicKey.getQ(),
            new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN()));
        signer.init(false, param);

        if (!signer.verifySignature(message, sig[0], sig[1]))
        {
            fail("ECGOST3410 2012 verification failed");
        }

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1]);
        }

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

        g.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"), new SecureRandom());

        KeyPair p = g.generateKeyPair();

        signatureGost12Test("ECGOST3410-2012-256", 64, p);
        encodedGost12Test(p);


        g.initialize(new org.bouncycastle.jcajce.spec.GOST3410ParameterSpec("Tc26-Gost-3410-12-512-paramSetA"), new SecureRandom());

        p = g.generateKeyPair();

        signatureGost12Test("ECGOST3410-2012-512", 128, p);
        encodedGost12Test(p);
    }

    private void ecGOST2012NameCurveGenerationTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");

        kpGen.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));

        KeyPair kp = kpGen.generateKeyPair();

        AlgorithmIdentifier expectedAlgId = new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                    new GOST3410PublicKeyAlgParameters(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256));

        checkKeyPairAlgId(kp, expectedAlgId);

        kpGen.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));

        kp = kpGen.generateKeyPair();

        expectedAlgId = new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                    new GOST3410PublicKeyAlgParameters(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512));

        checkKeyPairAlgId(kp, expectedAlgId);

        kpGen.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetB"));

        kp = kpGen.generateKeyPair();

        expectedAlgId = new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                    new GOST3410PublicKeyAlgParameters(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512));

        checkKeyPairAlgId(kp, expectedAlgId);

        kpGen.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetC"));

        kp = kpGen.generateKeyPair();

        expectedAlgId = new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                    new GOST3410PublicKeyAlgParameters(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512));

        checkKeyPairAlgId(kp, expectedAlgId);
    }

    private void checkKeyPairAlgId(KeyPair kp, AlgorithmIdentifier expectedAlgId)
    {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        AlgorithmIdentifier algId = info.getAlgorithm();

        isEquals(expectedAlgId, algId);

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        algId = privInfo.getPrivateKeyAlgorithm();

        isEquals(expectedAlgId, algId);
    }

    private void ecGOST34102012512Test()
        throws Exception
    {

        BigInteger r = new BigInteger("2489204477031349265072864643032147753667451319282131444027498637357611092810221795101871412928823716805959828708330284243653453085322004442442534151761462");
        BigInteger s = new BigInteger("864523221707669519038849297382936917075023735848431579919598799313385180564748877195639672460179421760770893278030956807690115822709903853682831835159370");

        BigInteger e = new BigInteger("2897963881682868575562827278553865049173745197871825199562947419041388950970536661109553499954248733088719748844538964641281654463513296973827706272045964");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1", 16));
        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger mod_p = new BigInteger("3623986102229003635907788753683874306021320925534678605086546150450856166624002482588482022271496854025090823603058735163734263822371964987228582907372403");
        BigInteger mod_q = new BigInteger("3623986102229003635907788753683874306021320925534678605086546150450856166623969164898305032863068499961404079437936585455865192212970734808812618120619743");

        ECCurve curve = new ECCurve.Fp(
            mod_p,
            new BigInteger("7"), // a
            new BigInteger("1518655069210828534508950034714043154928747527740206436194018823352809982443793732829756914785974674866041605397883677596626326413990136959047435811826396"), // b
            mod_q, ECConstants.ONE);

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(
                new BigInteger("1928356944067022849399309401243137598997786635459507974357075491307766592685835441065557681003184874819658004903212332884252335830250729527632383493573274"), // x
                new BigInteger("2288728693371972859970012155529478416353562327329506180314497425931102860301572814141997072271708807066593850650334152381857347798885864807605098724013854")), // y
            mod_q, ECConstants.ONE);

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("610081804136373098219538153239847583006845519069531562982388135354890606301782255383608393423372379057665527595116827307025046458837440766121180466875860"), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.createPoint(
                new BigInteger("909546853002536596556690768669830310006929272546556281596372965370312498563182320436892870052842808608262832456858223580713780290717986855863433431150561"), // x
                new BigInteger("2921457203374425620632449734248415455640700823559488705164895837509539134297327397380287741428246088626609329139441895016863758984106326600572476822372076")), // y
            spec);

        KeyFactory f = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PrivateKey sKey = f.generatePrivate(priKey);
        PublicKey vKey = f.generatePublic(pubKey);


        ECGOST3410_2012Signer signer = new ECGOST3410_2012Signer();
        CipherParameters param = ECUtil.generatePrivateKeyParameter(sKey);

        signer.init(true, new ParametersWithRandom(param, k));

        byte[] rev = e.toByteArray();
        byte[] message = new byte[rev.length];
        for (int i = 0; i != rev.length; i++)
        {
            message[i] = rev[rev.length - 1 - i];
        }
        BigInteger[] sig = signer.generateSignature(message);

        ECPublicKey ecPublicKey = (ECPublicKey)vKey;
        param = new ECPublicKeyParameters(
            ecPublicKey.getQ(),
            new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN()));
        signer.init(false, param);

        if (!signer.verifySignature(message, sig[0], sig[1]))
        {
            fail("ECGOST3410 2012 verification failed");
        }

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1]);
        }


    }

    private void ecGOST2012VerifyTest(String signatureAlg, byte[] data, byte[] pubEnc, byte[] sig)
        throws Exception
    {
        KeyFactory keyFact = KeyFactory.getInstance("ECGOST3410-2012", "BC");

        PublicKey vKey = keyFact.generatePublic(new X509EncodedKeySpec(pubEnc));

        Signature s = Signature.getInstance(signatureAlg, "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sig))
        {
            fail(signatureAlg + " verification failed");
        }
    }

    private void signatureGost12Test(String signatureAlg, int expectedSignLen, KeyPair p)
        throws Exception
    {
        byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

        PrivateKey sKey = p.getPrivate();
        PublicKey vKey = p.getPublic();
        Signature s = Signature.getInstance(signatureAlg, "BC");
        s.initSign(sKey);

        s.update(data);

        byte[] sigBytes = s.sign();

        if (sigBytes.length != expectedSignLen)
        {
            fail(signatureAlg + " signature failed");
        }

        s = Signature.getInstance(signatureAlg, "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail(signatureAlg + " verification failed");
        }

    }

    private void encodedGost12Test(KeyPair p)
        throws Exception
    {
        PrivateKey sKey = p.getPrivate();
        PublicKey vKey = p.getPublic();

        KeyFactory f = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        X509EncodedKeySpec x509s = new X509EncodedKeySpec(vKey.getEncoded());
        ECPublicKey eck1 = (ECPublicKey)f.generatePublic(x509s);

        if (!eck1.getQ().equals(((ECPublicKey)vKey).getQ()))
        {
            fail("public number not decoded properly");
        }

        if (!eck1.getParameters().equals(((ECPublicKey)vKey).getParameters()))
        {
            fail("public parameters not decoded properly");
        }

        PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(sKey.getEncoded());
        ECPrivateKey eck2 = (ECPrivateKey)f.generatePrivate(pkcs8);

        if (!eck2.getD().equals(((ECPrivateKey)sKey).getD()))
        {
            fail("private number not decoded properly");
        }

        if (!eck2.getParameters().equals(((ECPrivateKey)sKey).getParameters()))
        {
            fail("private number not decoded properly");
        }

        eck2 = (ECPrivateKey)serializeDeserialize(sKey);
        if (!eck2.getD().equals(((ECPrivateKey)sKey).getD()))
        {
            fail("private number not decoded properly");
        }

        if (!eck2.getParameters().equals(((ECPrivateKey)sKey).getParameters()))
        {
            fail("private number not decoded properly");
        }

        checkEquals(eck2, sKey);

        if (!(eck2 instanceof PKCS12BagAttributeCarrier))
        {
            fail("private key not implementing PKCS12 attribute carrier");
        }

        eck1 = (ECPublicKey)serializeDeserialize(vKey);

        if (!eck1.getQ().equals(((ECPublicKey)vKey).getQ()))
        {
            fail("public number not decoded properly");
        }

        if (!eck1.getParameters().equals(((ECPublicKey)vKey).getParameters()))
        {
            fail("public parameters not decoded properly");
        }

        checkEquals(eck1, vKey);
    }

    private void keyStoreTest(PrivateKey sKey, PublicKey vKey)
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException, UnrecoverableKeyException
    {
        //
        // keystore test
        //
        KeyStore ks = KeyStore.getInstance("JKS");

        ks.load(null, null);

        //
        // create the certificate - version 3
        //
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal("CN=Test"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X509Principal("CN=Test"));
        certGen.setPublicKey(vKey);
        certGen.setSignatureAlgorithm("GOST3411withGOST3410");

        X509Certificate cert = certGen.generate(sKey, "BC");

        ks.setKeyEntry("gost", sKey, "gost".toCharArray(), new Certificate[]{cert});

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ks.store(bOut, "gost".toCharArray());

        ks = KeyStore.getInstance("JKS");

        ks.load(new ByteArrayInputStream(bOut.toByteArray()), "gost".toCharArray());

        PrivateKey gKey = (PrivateKey)ks.getKey("gost", "gost".toCharArray());
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

    private void parametersTest()
        throws Exception
    {
//                AlgorithmParameterGenerator a = AlgorithmParameterGenerator.getInstance("GOST3410", "BC");
//                a.init(512, random);
//                AlgorithmParameters params = a.generateParameters();
//
//                byte[] encodeParams = params.getEncoded();
//
//                AlgorithmParameters a2 = AlgorithmParameters.getInstance("GOST3410", "BC");
//                a2.init(encodeParams);
//
//                // a and a2 should be equivalent!
//                byte[] encodeParams_2 = a2.getEncoded();
//
//                if (!arrayEquals(encodeParams, encodeParams_2))
//                {
//                    fail("encode/decode parameters failed");
//                }

        GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_B.getId());

        KeyPairGenerator g = KeyPairGenerator.getInstance("GOST3410", "BC");
        g.initialize(gost3410P, new SecureRandom());
        KeyPair p = g.generateKeyPair();

        PrivateKey sKey = p.getPrivate();
        PublicKey vKey = p.getPublic();

        Signature s = Signature.getInstance("GOST3410", "BC");
        byte[] data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

        s.initSign(sKey);

        s.update(data);

        byte[] sigBytes = s.sign();

        s = Signature.getInstance("GOST3410", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("GOST3410 verification failed");
        }

        keyStoreTest(sKey, vKey);
    }

    private BigInteger[] decode(
        byte[] encoding)
    {
        byte[] r = new byte[32];
        byte[] s = new byte[32];

        System.arraycopy(encoding, 0, s, 0, 32);

        System.arraycopy(encoding, 32, r, 0, 32);

        BigInteger[] sig = new BigInteger[2];

        sig[0] = new BigInteger(1, r);
        sig[1] = new BigInteger(1, s);

        return sig;
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

    public String getName()
    {
        return "GOST3410/ECGOST3410/ECGOST3410 2012";
    }

    public void performTest()
        throws Exception
    {
        ecGOST3410Test();

        if (Security.getProvider("BC").containsKey("KeyFactory.ECGOST3410-2012"))
        {
            ecGOST34102012256Test();
            ecGOST34102012512Test();
            ecGOST2012NameCurveGenerationTest();
            ecGOST2012VerifyTest("ECGOST3410-2012-256", ecgostData, ecgost2012_256Key, ecgost2012_256Sig);
            ecGOST2012VerifyTest("ECGOST3410-2012-512", ecgostData, ecgost2012_512Key, ecgost2012_512Sig);
        }
        
        generationTest();
        parametersTest();
    }

    protected byte[] toByteArray(String input)
    {
        byte[] bytes = new byte[input.length()];

        for (int i = 0; i != bytes.length; i++)
        {
            bytes[i] = (byte)input.charAt(i);
        }

        return bytes;
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new GOST3410Test());
    }
}
