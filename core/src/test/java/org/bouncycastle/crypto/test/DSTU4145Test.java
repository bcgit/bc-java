package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSTU4145Signer;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomData;

public class DSTU4145Test
    extends SimpleTest
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    public static void main(String[] args)
    {
        runTest(new DSTU4145Test());
    }

    public String getName()
    {
        return "DSTU4145";
    }

    private void test163()
        throws Exception
    {
        SecureRandom random = new TestRandomData(Hex.decode("01025e40bd97db012b7a1d79de8e12932d247f61c6"));

        byte[] hash = Hex.decode("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
        for (int i = 0; i < hash.length / 2; i++)
        {
            byte tmp = hash[i];
            hash[i] = hash[hash.length - 1 - i];
            hash[hash.length - 1 - i] = tmp;
        }

        BigInteger r = new BigInteger("274ea2c0caa014a0d80a424f59ade7a93068d08a7", 16);
        BigInteger s = new BigInteger("2100d86957331832b8e8c230f5bd6a332b3615aca", 16);

        ECCurve.F2m curve = new ECCurve.F2m(163, 3, 6, 7, ONE, new BigInteger("5FF6108462A2DC8210AB403925E638A19C1455D21", 16));
        ECPoint P = curve.createPoint(new BigInteger("72d867f93a93ac27df9ff01affe74885c8c540420", 16), new BigInteger("0224a9c3947852b97c5599d5f4ab81122adc3fd9b", 16));
        BigInteger n = new BigInteger("400000000000000000002BEC12BE2262D39BCF14D", 16);

        BigInteger d = new BigInteger("183f60fdf7951ff47d67193f8d073790c1c9b5a3e", 16);
        ECPoint Q = P.multiply(d).negate();

        ECDomainParameters domain = new ECDomainParameters(curve, P, n);
        CipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

        DSTU4145Signer dstuSigner = new DSTU4145Signer();
        dstuSigner.init(true, privKey);
        BigInteger[] rs = dstuSigner.generateSignature(hash);

        if (rs[0].compareTo(r) != 0)
        {
            fail("r component wrong");
        }

        if (rs[1].compareTo(s) != 0)
        {
            fail("s component wrong");
        }

        dstuSigner.init(false, pubKey);
        if (!dstuSigner.verifySignature(hash, r, s))
        {
            fail("verification fails");
        }
    }

    private void test173()
        throws Exception
    {
        SecureRandom random = new TestRandomData(Hex.decode("0000137449348C1249971759D99C252FFE1E14D8B31F"));

        byte[] hash = Hex.decode("0137187EA862117EF1484289470ECAC802C5A651FDA8");
        for (int i = 0; i < hash.length / 2; i++)
        {
            byte tmp = hash[i];
            hash[i] = hash[hash.length - 1 - i];
            hash[hash.length - 1 - i] = tmp;
        }

        BigInteger r = new BigInteger("13ae89746386709cdbd237cc5ec20ca30004a82ead8", 16);
        BigInteger s = new BigInteger("3597912cdd093b3e711ccb74a79d3c4ab4c7cccdc60", 16);

        ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));
        ECPoint P = curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16));
        BigInteger n = new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16);

        BigInteger d = new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16);
        ECPoint Q = P.multiply(d).negate();

        ECDomainParameters domain = new ECDomainParameters(curve, P, n);
        CipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

        DSTU4145Signer dstuSigner = new DSTU4145Signer();
        dstuSigner.init(true, privKey);
        BigInteger[] rs = dstuSigner.generateSignature(hash);

        if (rs[0].compareTo(r) != 0)
        {
            fail("r component wrong");
        }

        if (rs[1].compareTo(s) != 0)
        {
            fail("s component wrong");
        }

        dstuSigner.init(false, pubKey);
        if (!dstuSigner.verifySignature(hash, r, s))
        {
            fail("verification fails");
        }
    }

    private void test283()
        throws Exception
    {
        SecureRandom random = new TestRandomData(Hex.decode("00000000245383CB3AD41BF30F5F7E8FBA858509B2D5558C92D539A6D994BFA98BC6940E"));

        byte[] hash = Hex.decode("0137187EA862117EF1484289470ECAC802C5A651FDA8");
        for (int i = 0; i < hash.length / 2; i++)
        {
            byte tmp = hash[i];
            hash[i] = hash[hash.length - 1 - i];
            hash[hash.length - 1 - i] = tmp;
        }

        BigInteger r = new BigInteger("12a5edcc38d92208ff23036d75b000c7e4bc0f9af2d40b35f15d6fd15e01234e67781a8", 16);
        BigInteger s = new BigInteger("2de0775577f75b643cf5afc80d4fe10b21100690f17e2cab7bdc9b50ec87c5727aeb515", 16);

        ECCurve.F2m curve = new ECCurve.F2m(283, 5, 7, 12, ONE, new BigInteger("27B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5", 16));
        ECPoint P = curve.createPoint(new BigInteger("4D95820ACE761110824CE425C8089129487389B7F0E0A9D043DDC0BB0A4CC9EB25", 16), new BigInteger("954C9C4029B2C62DE35C2B9C2A164984BF1101951E3A68ED03DF234DDE5BB2013152F2", 16));
        BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307", 16);

        BigInteger d = new BigInteger("B844EEAF15213E4BAD4FB84796D68F2448DB8EB7B4621EC0D51929874892C43E", 16);
        ECPoint Q = P.multiply(d).negate();

        ECDomainParameters domain = new ECDomainParameters(curve, P, n);
        CipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

        DSTU4145Signer dstuSigner = new DSTU4145Signer();
        dstuSigner.init(true, privKey);
        BigInteger[] rs = dstuSigner.generateSignature(hash);

        if (rs[0].compareTo(r) != 0)
        {
            fail("r component wrong");
        }

        if (rs[1].compareTo(s) != 0)
        {
            fail("s component wrong");
        }

        dstuSigner.init(false, pubKey);
        if (!dstuSigner.verifySignature(hash, r, s))
        {
            fail("verification fails");
        }
    }

    private void test431()
        throws Exception
    {
        SecureRandom random = new TestRandomData(Hex.decode("0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3871C2073AD75AB530457"));

        byte[] hash = Hex.decode("0137187EA862117EF1484289470ECAC802C5A651FDA8");
        for (int i = 0; i < hash.length / 2; i++)
        {
            byte tmp = hash[i];
            hash[i] = hash[hash.length - 1 - i];
            hash[hash.length - 1 - i] = tmp;
        }

        BigInteger r = new BigInteger("1911fefb1f494bebcf8dffdf5276946ff9c9f662192ee18c718db47310a439c784fe07577b16e1edbe16179876e0792a634f1c9c3a2e", 16);
        BigInteger s = new BigInteger("3852170ee801c2083c52f1ea77b987a5432acecd9c654f064e87bf179e0a397151edbca430082e43bd38a67b55424b5bbc7f2713f620", 16);

        ECCurve.F2m curve = new ECCurve.F2m(431, 1, 3, 5, ONE, new BigInteger("3CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", 16));
        ECPoint P = curve.createPoint(new BigInteger("9548BCDF314CEEEAF099C780FFEFBF93F9FE5B5F55547603C9C8FC1A2774170882B3BE35E892C6D4296B8DEA282EC30FB344272791", 16), new BigInteger("4C6CBD7C62A8EEEFDE17A8B5E196E49A22CE6DE128ABD9FBD81FA4411AD5A38E2A810BEDE09A7C6226BCDCB4A4A5DA37B4725E00AA74", 16));
        BigInteger n = new BigInteger("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16);

        BigInteger d = new BigInteger("D0F97354E314191FD773E2404F478C8AEE0FF5109F39E6F37D1FEEC8B2ED1691D84C9882CC729E716A71CC013F66CAC60E29E22C", 16);
        ECPoint Q = P.multiply(d).negate();

        ECDomainParameters domain = new ECDomainParameters(curve, P, n);
        CipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

        DSTU4145Signer dstuSigner = new DSTU4145Signer();
        dstuSigner.init(true, privKey);
        BigInteger[] rs = dstuSigner.generateSignature(hash);

        if (rs[0].compareTo(r) != 0)
        {
            fail("r component wrong");
        }

        if (rs[1].compareTo(s) != 0)
        {
            fail("s component wrong");
        }

        dstuSigner.init(false, pubKey);
        if (!dstuSigner.verifySignature(hash, r, s))
        {
            fail("verification fails");
        }
    }

    private void testTruncation()
    {
        SecureRandom random = new TestRandomData(Hex.decode("0000C4224DBBD800988DBAA39DE838294C345CDA5F5929D1174AA8D9340A5E79D10ACADE6B53CF873E7301A3871C2073AD75AB530457"));

        // use extra long "hash" with set bits...
        byte[] hash = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

        ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));
        ECPoint P = curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16));
        BigInteger n = new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16);

        BigInteger d = new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16);
        ECPoint Q = P.multiply(d).negate();

        ECDomainParameters domain = new ECDomainParameters(curve, P, n);
        CipherParameters privKey = new ParametersWithRandom(new ECPrivateKeyParameters(d, domain), random);
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Q, domain);

        DSTU4145Signer dstuSigner = new DSTU4145Signer();
        dstuSigner.init(true, privKey);
        BigInteger[] rs = dstuSigner.generateSignature(hash);

        BigInteger r = new BigInteger("6bb5c0cb82e5067485458ebfe81025f03b687c63a27", 16);
        BigInteger s = new BigInteger("34d6b1868969b86ecf934167c8fe352c63d1074bd", 16);

        if (rs[0].compareTo(r) != 0)
        {
            fail("r component wrong");
        }

        if (rs[1].compareTo(s) != 0)
        {
            fail("s component wrong");
        }

        dstuSigner.init(false, pubKey);
        if (!dstuSigner.verifySignature(hash, rs[0], rs[1]))
        {
            fail("verification fails");
        }
    }

    public void performTest()
        throws Exception
    {
        test163();
        test173();
        test283();
        test431();
        testTruncation();
    }

}
