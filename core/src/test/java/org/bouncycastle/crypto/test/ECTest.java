package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.StagedAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCStagedAgreement;
import org.bouncycastle.crypto.agreement.ECDHCUnifiedAgreement;
import org.bouncycastle.crypto.agreement.ECMQVBasicAgreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDHUPrivateParameters;
import org.bouncycastle.crypto.params.ECDHUPublicParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.MQVPrivateParameters;
import org.bouncycastle.crypto.params.MQVPublicParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * ECDSA tests are taken from X9.62.
 */
public class ECTest
    extends SimpleTest
{
    /**
     * X9.62 - 1998,<br>
     * J.3.1, Page 152, ECDSA over the field Fp<br>
     * an example with 192 bit prime
     */
    private void testECDSA192bitPrime()
    {
        BigInteger r = new BigInteger("3342403536405981729393488334694600415596881826869351677613");
        BigInteger s = new BigInteger("5735822328888155254683894997897571951568553642892029982342");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("6140507067065001063065065565667405560006161556565665656654"));

        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("6277101735386680763835789423207666416083908700390324961279"), // q
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16), // a
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("651056770906015076056810763456358567190100156695615665659"), // d
            params);

        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ECDSASigner ecdsa = new ECDSASigner();

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("verification fails");
        }
    }

    private void decodeTest()
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("prime192v1");
        ECPoint p = x9.getG();

        if (!p.getAffineXCoord().toBigInteger().equals(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)))
        {
            fail("x uncompressed incorrectly");
        }

        if (!p.getAffineYCoord().toBigInteger().equals(new BigInteger("7192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)))
        {
            fail("y uncompressed incorrectly");
        }

        byte[] encoding = p.getEncoded(true);

        if (!areEqual(encoding, Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")))
        {
            fail("point compressed incorrectly");
        }
    }

    /**
     * X9.62 - 1998,<br>
     * J.3.2, Page 155, ECDSA over the field Fp<br>
     * an example with 239 bit prime
     */
    private void testECDSA239bitPrime()
    {
        BigInteger r = new BigInteger("308636143175167811492622547300668018854959378758531778147462058306432176");
        BigInteger s = new BigInteger("323813553209797357708078776831250505931891051755007842781978505179448783");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            params);

        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }


    /**
     * X9.62 - 1998,<br>
     * J.2.1, Page 100, ECDSA over the field F2m<br>
     * an example with 191 bit binary field
     */
    private void testECDSA191bitBinary()
    {
        BigInteger r = new BigInteger("87194383164871543355722284926904419997237591535066528048");
        BigInteger s = new BigInteger("308992691965804947361541664549085895292153777025772063598");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("1542725565216523985789236956265265265235675811949404040041"));

        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger n = new BigInteger("1569275433846670190958947355803350458831205595451630533029");
        BigInteger h = BigInteger.valueOf(2);

        ECCurve.F2m curve = new ECCurve.F2m(
            191, // m
            9, //k
            new BigInteger("2866537B676752636A68F56554E12640276B649EF7526267", 16), // a
            new BigInteger("2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC", 16), // b
            n, h);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("0436B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D765BE73433B3F95E332932E70EA245CA2418EA0EF98018FB")), // G
            n, h);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("1275552191113212300012030439187146164646146646466749494799"), // d
            params);

        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("045DE37E756BD55D72E3768CB396FFEB962614DEA4CE28A2E755C0E0E02F5FB132CAF416EF85B229BBB8E1352003125BA1")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }


    /**
     * X9.62 - 1998,<br>
     * J.2.1, Page 100, ECDSA over the field F2m<br>
     * an example with 191 bit binary field
     */
    private void testECDSA239bitBinary()
    {
        BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
        BigInteger s = new BigInteger("197030374000731686738334997654997227052849804072198819102649413465737174");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger n = new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783");
        BigInteger h = BigInteger.valueOf(4);

        ECCurve.F2m curve = new ECCurve.F2m(
            239, // m
            36, //k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16), // b
            n, h);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            n, h);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);

        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    // L 4.1  X9.62 2005
    private void testECDSAP224sha224()
    {
        X9ECParameters p = NISTNamedCurves.getByName("P-224");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("6081831502424510080126737029209236539191290354021104541805484120491"), // d
            params);
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("15456715103636396133226117016818339719732885723579037388121116732601")));

        byte[] M = Hex.decode("8797A3C693CC292441039A4E6BAB7387F3B4F2A63D00ED384B378C79");

        ECDSASigner dsa = new ECDSASigner();

        dsa.init(true, new ParametersWithRandom(priKey, k));

        BigInteger[] sig = dsa.generateSignature(M);

        BigInteger r = new BigInteger("26477406756127720855365980332052585411804331993436302005017227573742");
        BigInteger s = new BigInteger("17694958233103667059888193972742186995283044672015112738919822429978");

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("03FD44EC11F9D43D9D23B1E1D1C9ED6519B40ECF0C79F48CF476CC43F1")), // Q
            params);

        dsa.init(false, pubKey);
        if (!dsa.verifySignature(M, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    private void testECDSASecP224k1sha256()
    {
        X9ECParameters p = SECNamedCurves.getByName("secp224k1");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("BE6F6E91FE96840A6518B56F3FE21689903A64FA729057AB872A9F51", 16), // d
            params);
        SecureRandom k = new TestRandomBigInteger(Hex.decode("00c39beac93db21c3266084429eb9b846b787c094f23a4de66447efbb3"));

        byte[] M = Hex.decode("E5D5A7ADF73C5476FAEE93A2C76CE94DC0557DB04CDC189504779117920B896D");

        ECDSASigner dsa = new ECDSASigner();

        dsa.init(true, new ParametersWithRandom(priKey, k));

        BigInteger[] sig = dsa.generateSignature(M);

        BigInteger r = new BigInteger("8163E5941BED41DA441B33E653C632A55A110893133351E20CE7CB75", 16);
        BigInteger s = new BigInteger("D12C3FC289DDD5F6890DCE26B65792C8C50E68BF551D617D47DF15A8", 16);

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("04C5C9B38D3603FCCD6994CBB9594E152B658721E483669BB42728520F484B537647EC816E58A8284D3B89DFEDB173AFDC214ECA95A836FA7C")), // Q
            params);

        dsa.init(false, pubKey);
        if (!dsa.verifySignature(M, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    // L4.2  X9.62 2005
    private void testECDSAP256sha256()
    {
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), // d
            params);
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335")));

        byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

        ECDSASigner dsa = new ECDSASigner();

        dsa.init(true, new ParametersWithRandom(priKey, k));

        BigInteger[] sig = dsa.generateSignature(M);

        BigInteger r = new BigInteger("97354732615802252173078420023658453040116611318111190383344590814578738210384");
        BigInteger s = new BigInteger("98506158880355671805367324764306888225238061309262649376965428126566081727535");

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), // Q
            params);

        dsa.init(false, pubKey);
        if (!dsa.verifySignature(M, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    private void testECDSAP256sha3(int size, BigInteger s)
    {
        X9ECParameters p = NISTNamedCurves.getByName("P-256");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("20186677036482506117540275567393538695075300175221296989956723148347484984008"), // d
            params);
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335")));

        byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

        DSADigestSigner dsa = new DSADigestSigner(new ECDSASigner(), new SHA3Digest(size));

        dsa.init(true, new ParametersWithRandom(priKey, k));

        dsa.update(M, 0, M.length);

        byte[] encSig = dsa.generateSignature();

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
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("03596375E6CE57E0F20294FC46BDFCFD19A39F8161B58695B3EC5B3D16427C274D")), // Q
            params);

        dsa.init(false, pubKey);

        dsa.update(M, 0, M.length);

        if (!dsa.verifySignature(encSig))
        {
            fail("signature fails");
        }
    }

    private void testECDSAP224OneByteOver()
    {
        X9ECParameters p = NISTNamedCurves.getByName("P-224");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("6081831502424510080126737029209236539191290354021104541805484120491"), // d
            params);
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("15456715103636396133226117016818339719732885723579037388121116732601")));

        byte[] M = Hex.decode("8797A3C693CC292441039A4E6BAB7387F3B4F2A63D00ED384B378C79FF");

        ECDSASigner dsa = new ECDSASigner();

        dsa.init(true, new ParametersWithRandom(priKey, k));

        BigInteger[] sig = dsa.generateSignature(M);

        BigInteger r = new BigInteger("26477406756127720855365980332052585411804331993436302005017227573742");
        BigInteger s = new BigInteger("17694958233103667059888193972742186995283044672015112738919822429978");

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("03FD44EC11F9D43D9D23B1E1D1C9ED6519B40ECF0C79F48CF476CC43F1")), // Q
            params);

        dsa.init(false, pubKey);
        if (!dsa.verifySignature(M, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    // L4.3  X9.62 2005
    private void testECDSAP521sha512()
    {
        X9ECParameters p = NISTNamedCurves.getByName("P-521");
        ECDomainParameters params = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("617573726813476282316253885608633222275541026607493641741273231656161177732180358888434629562647985511298272498852936680947729040673640492310550142822667389"), // d
            params);
        SecureRandom k = new TestRandomBigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("6806532878215503520845109818432174847616958675335397773700324097584974639728725689481598054743894544060040710846048585856076812050552869216017728862957612913")));

        byte[] M = Hex.decode("6893B64BD3A9615C39C3E62DDD269C2BAAF1D85915526083183CE14C2E883B48B193607C1ED871852C9DF9C3147B574DC1526C55DE1FE263A676346A20028A66");

        ECDSASigner dsa = new ECDSASigner();

        dsa.init(true, new ParametersWithRandom(priKey, k));

        BigInteger[] sig = dsa.generateSignature(M);

        BigInteger r = new BigInteger("1368926195812127407956140744722257403535864168182534321188553460365652865686040549247096155740756318290773648848859639978618869784291633651685766829574104630");
        BigInteger s = new BigInteger("1624754720348883715608122151214003032398685415003935734485445999065609979304811509538477657407457976246218976767156629169821116579317401249024208611945405790");

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            params.getCurve().decodePoint(Hex.decode("020145E221AB9F71C5FE740D8D2B94939A09E2816E2167A7D058125A06A80C014F553E8D6764B048FB6F2B687CEC72F39738F223D4CE6AFCBFF2E34774AA5D3C342CB3")), // Q
            params);

        dsa.init(false, pubKey);
        if (!dsa.verifySignature(M, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * General test for long digest.
     */
    private void testECDSA239bitBinaryAndLargeDigest()
    {
        BigInteger r = new BigInteger("21596333210419611985018340039034612628818151486841789642455876922391552");
        BigInteger s = new BigInteger("144940322424411242416373536877786566515839911620497068645600824084578597");

        byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("171278725565216523967285789236956265265265235675811949404040041670216363"));

        SecureRandom k = new TestRandomBigInteger(kData);

        BigInteger n = new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783");
        BigInteger h = BigInteger.valueOf(4);

        ECCurve.F2m curve = new ECCurve.F2m(
            239, // m
            36, //k
            new BigInteger("32010857077C5431123A46B808906756F543423E8D27877578125778AC76", 16), // a
            new BigInteger("790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16", 16), // b
            n, h);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305")), // G
            n, h);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
            params);

        ECDSASigner ecdsa = new ECDSASigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517968236873715988614170569073515315707566766479517968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

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

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5")), // Q
            params);

        ecdsa.init(false, pubKey);
        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * key generation test
     */
    private void testECDSAKeyGenTest()
    {
        SecureRandom random = new SecureRandom();

        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n);

        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(
            params,
            random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair pair = pGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        ECDSASigner ecdsa = new ECDSASigner();

        ecdsa.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecdsa.generateSignature(message);

        ecdsa.init(false, pair.getPublic());

        if (!ecdsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * Basic Key Agreement Test
     */
    private void testECDHBasicAgreement()
    {
        SecureRandom random = new SecureRandom();

        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n);

        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(
            params,
            random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();
        AsymmetricCipherKeyPair p2 = pGen.generateKeyPair();

        //
        // two way
        //
        BasicAgreement e1 = new ECDHBasicAgreement();
        BasicAgreement e2 = new ECDHBasicAgreement();

        e1.init(p1.getPrivate());
        e2.init(p2.getPrivate());

        BigInteger k1 = e1.calculateAgreement(p2.getPublic());
        BigInteger k2 = e2.calculateAgreement(p1.getPublic());

        if (!k1.equals(k2))
        {
            fail("calculated agreement test failed");
        }

        //
        // two way
        //
        e1 = new ECDHCBasicAgreement();
        e2 = new ECDHCBasicAgreement();

        e1.init(p1.getPrivate());
        e2.init(p2.getPrivate());

        k1 = e1.calculateAgreement(p2.getPublic());
        k2 = e2.calculateAgreement(p1.getPublic());

        if (!k1.equals(k2))
        {
            fail("calculated agreement test failed");
        }
    }

    private void testECDHBasicAgreementCofactor()
    {
        SecureRandom random = new SecureRandom();

        X9ECParameters x9 = CustomNamedCurves.getByName("curve25519");
        ECDomainParameters ec = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(ec, random));

        AsymmetricCipherKeyPair p1 = kpg.generateKeyPair();
        AsymmetricCipherKeyPair p2 = kpg.generateKeyPair();

        BasicAgreement e1 = new ECDHBasicAgreement();
        BasicAgreement e2 = new ECDHBasicAgreement();

        e1.init(p1.getPrivate());
        e2.init(p2.getPrivate());

        BigInteger k1 = e1.calculateAgreement(p2.getPublic());
        BigInteger k2 = e2.calculateAgreement(p1.getPublic());

        if (!k1.equals(k2))
        {
            fail("calculated agreement test failed");
        }
    }

    private void testECDHStagedAgreement()
    {
        SecureRandom random = new SecureRandom();

        X9ECParameters x9 = CustomNamedCurves.getByName("curve25519");
        ECDomainParameters ec = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(ec, random));

        AsymmetricCipherKeyPair p1 = kpg.generateKeyPair();
        AsymmetricCipherKeyPair p2 = kpg.generateKeyPair();
        AsymmetricCipherKeyPair p3 = kpg.generateKeyPair();

        StagedAgreement e1 = new ECDHCStagedAgreement();
        StagedAgreement e2 = new ECDHCStagedAgreement();
        StagedAgreement e3 = new ECDHCStagedAgreement();

        e1.init(p1.getPrivate());
        e2.init(p2.getPrivate());
        e3.init(p3.getPrivate());

        AsymmetricKeyParameter stage1_12 = e1.calculateStage(p2.getPublic());
        AsymmetricKeyParameter stage1_23 = e2.calculateStage(p3.getPublic());
        AsymmetricKeyParameter stage1_31 = e3.calculateStage(p1.getPublic());

        BigInteger k1 = e1.calculateAgreement(stage1_23);
        BigInteger k2 = e2.calculateAgreement(stage1_31);
        BigInteger k3 = e3.calculateAgreement(stage1_12);

        if (!k1.equals(k2))
        {
            fail("1-2 calculated agreement test failed");
        }

        if (!k3.equals(k2))
        {
            fail("3-2 calculated agreement test failed");
        }
    }

    private void testECMQVTestVector1()
    {
        // Test Vector from GEC-2

        X9ECParameters x9 = SECNamedCurves.getByName("secp160r1");
        ECDomainParameters p = new ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        AsymmetricCipherKeyPair U1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("0251B4496FECC406ED0E75A24A3C03206251419DC0")), p),
            new ECPrivateKeyParameters(
                new BigInteger("AA374FFC3CE144E6B073307972CB6D57B2A4E982", 16), p));

        AsymmetricCipherKeyPair U2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("03D99CE4D8BF52FA20BD21A962C6556B0F71F4CA1F")), p),
            new ECPrivateKeyParameters(
                new BigInteger("149EC7EA3A220A887619B3F9E5B4CA51C7D1779C", 16), p));

        AsymmetricCipherKeyPair V1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("0349B41E0E9C0369C2328739D90F63D56707C6E5BC")), p),
            new ECPrivateKeyParameters(
                new BigInteger("45FB58A92A17AD4B15101C66E74F277E2B460866", 16), p));

        AsymmetricCipherKeyPair V2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("02706E5D6E1F640C6E9C804E75DBC14521B1E5F3B5")), p),
            new ECPrivateKeyParameters(
                new BigInteger("18C13FCED9EADF884F7C595C8CB565DEFD0CB41E", 16), p));

        BigInteger x = calculateAgreement(U1, U2, V1, V2);

        if (x == null
            || !x.equals(new BigInteger("5A6955CEFDB4E43255FB7FCF718611E4DF8E05AC", 16)))
        {
            fail("MQV Test Vector #1 agreement failed");
        }
    }

    private void testECMQVTestVector2()
    {
        // Test Vector from GEC-2

        X9ECParameters x9 = SECNamedCurves.getByName("sect163k1");
        ECDomainParameters p = new ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        AsymmetricCipherKeyPair U1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("03037D529FA37E42195F10111127FFB2BB38644806BC")), p),
            new ECPrivateKeyParameters(
                new BigInteger("03A41434AA99C2EF40C8495B2ED9739CB2155A1E0D", 16), p));

        AsymmetricCipherKeyPair U2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("02015198E74BC2F1E5C9A62B80248DF0D62B9ADF8429")), p),
            new ECPrivateKeyParameters(
                new BigInteger("032FC4C61A8211E6A7C4B8B0C03CF35F7CF20DBD52", 16), p));

        AsymmetricCipherKeyPair V1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("03072783FAAB9549002B4F13140B88132D1C75B3886C")), p),
            new ECPrivateKeyParameters(
                new BigInteger("57E8A78E842BF4ACD5C315AA0569DB1703541D96", 16), p));

        AsymmetricCipherKeyPair V2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("03067E3AEA3510D69E8EDD19CB2A703DDC6CF5E56E32")), p),
            new ECPrivateKeyParameters(
                new BigInteger("02BD198B83A667A8D908EA1E6F90FD5C6D695DE94F", 16), p));

        BigInteger x = calculateAgreement(U1, U2, V1, V2);

        if (x == null
            || !x.equals(new BigInteger("038359FFD30C0D5FC1E6154F483B73D43E5CF2B503", 16)))
        {
            fail("MQV Test Vector #2 agreement failed");
        }
    }

    private void testECMQVRandom()
    {
        SecureRandom random = new SecureRandom();

        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters parameters = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n);

        ECKeyPairGenerator pGen = new ECKeyPairGenerator();

        pGen.init(new ECKeyGenerationParameters(parameters, random));


        // Pre-established key pairs
        AsymmetricCipherKeyPair U1 = pGen.generateKeyPair();
        AsymmetricCipherKeyPair V1 = pGen.generateKeyPair();

        // Ephemeral key pairs
        AsymmetricCipherKeyPair U2 = pGen.generateKeyPair();
        AsymmetricCipherKeyPair V2 = pGen.generateKeyPair();

        BigInteger x = calculateAgreement(U1, U2, V1, V2);

        if (x == null)
        {
            fail("MQV Test Vector (random) agreement failed");
        }
    }

    private static BigInteger calculateAgreement(
        AsymmetricCipherKeyPair U1,
        AsymmetricCipherKeyPair U2,
        AsymmetricCipherKeyPair V1,
        AsymmetricCipherKeyPair V2)
    {
        ECMQVBasicAgreement u = new ECMQVBasicAgreement();
        u.init(new MQVPrivateParameters(
            (ECPrivateKeyParameters)U1.getPrivate(),
            (ECPrivateKeyParameters)U2.getPrivate(),
            (ECPublicKeyParameters)U2.getPublic()));
        BigInteger ux = u.calculateAgreement(new MQVPublicParameters(
            (ECPublicKeyParameters)V1.getPublic(),
            (ECPublicKeyParameters)V2.getPublic()));

        ECMQVBasicAgreement v = new ECMQVBasicAgreement();
        v.init(new MQVPrivateParameters(
            (ECPrivateKeyParameters)V1.getPrivate(),
            (ECPrivateKeyParameters)V2.getPrivate(),
            (ECPublicKeyParameters)V2.getPublic()));
        BigInteger vx = v.calculateAgreement(new MQVPublicParameters(
            (ECPublicKeyParameters)U1.getPublic(),
            (ECPublicKeyParameters)U2.getPublic()));

        if (ux.equals(vx))
        {
            return ux;
        }

        return null;
    }

    private void testECUnifiedTestVector1()
    {
        // Test Vector from NIST sample data

        X9ECParameters x9 = NISTNamedCurves.getByName("P-224");
        ECDomainParameters p = new ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        AsymmetricCipherKeyPair U1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("040784e946ef1fae0cfe127042a310a018ba639d3f6b41f265904f0a7b21b7953efe638b45e6c0c0d34a883a510ce836d143d831daa9ce8a12")), p),
            new ECPrivateKeyParameters(
                new BigInteger("86d1735ca357890aeec8eccb4859275151356ecee9f1b2effb76b092", 16), p));

        AsymmetricCipherKeyPair U2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("04b33713dc0d56215be26ee6c5e60ad36d12e02e78529ae3ff07873c6b39598bda41c1cf86ee3981f40e102333c15fef214bda034291c1aca6")), p),
            new ECPrivateKeyParameters(
                new BigInteger("764010b3137ef8d34a3552955ada572a4fa1bb1f5289f27c1bf18344", 16), p));

        AsymmetricCipherKeyPair V1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("0484c22d9575d09e280613c8758467f84869c6eede4f6c1b644517d6a72c4fc5c68fa12b4c259032fc5949c630259948fca38fb3342d9cb0a8")), p),
            new ECPrivateKeyParameters(
                new BigInteger("e37964e391f5058fb43435352a9913438a1ec10831f755273285230a", 16), p));

        AsymmetricCipherKeyPair V2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("044b917e9ce693b277c8095e535ea81c2dea089446a8c55438eda750fb6170c85b86390481fff2dff94b7dff3e42d35ff623921cb558967b48")), p),
            new ECPrivateKeyParameters(
                new BigInteger("ab40d67f59ba7265d8ad33ade8f704d13a7ba2298b69172a7cd02515", 16), p));

        byte[] x = calculateUnifiedAgreement(U1, U2, V1, V2);

        if (x == null
            || !areEqual(Hex.decode("80315a208b1cd6119264e5c03242b7db96379986fdc4c2f06bf88d0655cda75d4dc7e94a8df9f03239d5da9a18d364cebc6c63f01b6f4378"), x))
        {
            fail("EC combined Test Vector #1 agreement failed");
        }
    }

    private void testECUnifiedTestVector2()
    {
        // Test Vector from NIST sample data

        X9ECParameters x9 = NISTNamedCurves.getByName("P-256");
        ECDomainParameters p = new ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        AsymmetricCipherKeyPair U1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("047581b35964a983414ebdd56f4ebb1ddcad10881b200666a51ae41306e1ecf1db368468a5e8a65ca10ccea526472c8982db68316c468800e171c11f4ee694fce4")), p),
            new ECPrivateKeyParameters(
                new BigInteger("2eb7ef76d4936123b6f13035045aedf45c1c7731f35d529d25941926b5bb38bb", 16), p));

        AsymmetricCipherKeyPair U2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("045b1e4cdeb0728333c0a51631b1a75269e4878d10732f4cb94d600483db4bd9ee625c374592c3db7e9f8b4f2c91a0098a158bc37b922e4243bd9cbdefe67d6ab0")), p),
            new ECPrivateKeyParameters(
                new BigInteger("78acde388a022261767e6b3dd6dd016c53b70a084260ec87d395aec761c082de", 16), p));

        AsymmetricCipherKeyPair V1 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("04e4916d616803ff1bd9569f35b7d06f792f19c1fb4e6fa916d686c027a17d8dffd570193d8e101624ac2ea0bcb762d5613f05452670f09af66ef70861fb528868")), p),
            new ECPrivateKeyParameters(
                new BigInteger("9c85898640a1b1de8ce7f557492dc1460530b9e17afaaf742eb953bb644e9c5a", 16), p));

        AsymmetricCipherKeyPair V2 = new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(
                p.getCurve().decodePoint(Hex.decode("04d1cd23c29d0fc865c316d44a1fd5adb6605ee47c9ddfec3a9b0a5e532d52704e74ff5d149aeb50856fefb38d5907b6dbb580fe6dc166bcfcbee4eb376d77e95c")), p),
            new ECPrivateKeyParameters(
                new BigInteger("d6e11d5d3b85b201b8f4c12dadfad3000e267961a806a0658a2b859d44389599", 16), p));

        byte[] x = calculateUnifiedAgreement(U1, U2, V1, V2);

        if (x == null
            || !areEqual(Hex.decode("02886e53998b06d92f04e4579cbfa5f35c96334d3890298264e7f956da70966af07bf1b3abbaa8d76fbaf435508bdabbbbbdae1a191d91480ed88374c3552233"), x))
        {
            fail("EC combined Test Vector #2 agreement failed");
        }
    }

    private byte[] calculateUnifiedAgreement(
        AsymmetricCipherKeyPair U1,
        AsymmetricCipherKeyPair U2,
        AsymmetricCipherKeyPair V1,
        AsymmetricCipherKeyPair V2)
    {
        ECDHCUnifiedAgreement u = new ECDHCUnifiedAgreement();
        u.init(new ECDHUPrivateParameters(
            (ECPrivateKeyParameters)U1.getPrivate(),
            (ECPrivateKeyParameters)U2.getPrivate(),
            (ECPublicKeyParameters)U2.getPublic()));
        byte[] ux = u.calculateAgreement(new ECDHUPublicParameters(
            (ECPublicKeyParameters)V1.getPublic(),
            (ECPublicKeyParameters)V2.getPublic()));

        ECDHCUnifiedAgreement v = new ECDHCUnifiedAgreement();
        v.init(new ECDHUPrivateParameters(
            (ECPrivateKeyParameters)V1.getPrivate(),
            (ECPrivateKeyParameters)V2.getPrivate(),
            (ECPublicKeyParameters)V2.getPublic()));
        byte[] vx = v.calculateAgreement(new ECDHUPublicParameters(
            (ECPublicKeyParameters)U1.getPublic(),
            (ECPublicKeyParameters)U2.getPublic()));

        if (areEqual(ux, vx))
        {
            return ux;
        }

        return null;
    }

    public String getName()
    {
        return "EC";
    }

    public void performTest()
    {
        decodeTest();
        testECDSA192bitPrime();
        testECDSA239bitPrime();
        testECDSA191bitBinary();
        testECDSA239bitBinary();
        testECDSAKeyGenTest();
        testECDHBasicAgreement();
        testECDHBasicAgreementCofactor();

        testECDSAP224sha224();
        testECDSAP224OneByteOver();
        testECDSAP256sha256();
        testECDSAP521sha512();
        testECDSASecP224k1sha256();
        testECDSA239bitBinaryAndLargeDigest();

        testECDSAP256sha3(224, new BigInteger("84d7d8e68e405064109cd9fc3e3026d74d278aada14ce6b7a9dd0380c154dc94", 16));
        testECDSAP256sha3(256, new BigInteger("99a43bdab4af989aaf2899079375642f2bae2dce05bcd8b72ec8c4a8d9a143f", 16));
        testECDSAP256sha3(384, new BigInteger("aa27726509c37aaf601de6f7e01e11c19add99530c9848381c23365dc505b11a", 16));
        testECDSAP256sha3(512, new BigInteger("f8306b57a1f5068bf12e53aabaae39e2658db39bc56747eaefb479995130ad16", 16));

        testECMQVTestVector1();
        testECMQVTestVector2();
        testECMQVRandom();

        testECUnifiedTestVector1();
        testECUnifiedTestVector2();

        testECDHStagedAgreement();
    }


    public static void main(
        String[] args)
    {
        runTest(new ECTest());
    }
}

