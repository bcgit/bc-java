package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.util.Collections;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class CryptoServiceConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "CryptoServiceConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        test112bits();
        test128bits();
        testLegacy128bits();
        test1024bitDSA();
        test1024bitRSA();
        testSerpent();
        testTwofish();
        testSkipjack();
        testMD2();
        testMD4();
        testMD5();
        testSHA1();
        testSHA224();
        testSHA256();
        testSHA384();
        testSHA512();
        testSHA3();
        testDSTU7564();
        testAES();
        testAESFast();
        testAESLight();
        testARIA();
    }

    private void test112bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112));

        try
        {
            new RC4Engine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 20", e.getMessage());
        }

        // try with exception for RC4/ARC4
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(112, Collections.singleton("ARC4")));

        new RC4Engine();

        try
        {
            new DESEngine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 56", e.getMessage());
        }

        new DESedeEngine();

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test128bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new DESedeEngine();
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 112", e.getMessage());
        }

        // add exception for DESede
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128, Collections.singleton("DESede")));

        new DESedeEngine();

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testLegacy128bits()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));

        DESedeEngine eng = new DESedeEngine();
        KeyParameter dKey = new KeyParameter(Hex.decode("01020304050607080102030405060708"));

        try
        {
            eng.init(true, dKey);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        eng.init(false, dKey);     // this should work as we are decrypting

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test1024bitDSA()
    {
        BigInteger p = new BigInteger(
            "17801190547854226652823756245015999014523215636912067427327445031"
            + "444286578873702077061269525212346307956715678477846644997065077092072"
            + "785705000966838814403412974522117181850604723115003930107995935806739"
            + "534871706631980226201971496652413506094591370759495651467285569060679"
            + "4135837542707371727429551343320695239");
        BigInteger q = new BigInteger("864205495604807476120572616017955259175325408501");
        BigInteger g = new BigInteger(
            "17406820753240209518581198012352343653860449079456135097849583104"
            + "059995348845582314785159740894095072530779709491575949236830057425243"
            + "876103708447346718014887611810308304375498519098347260155049469132948"
            + "808339549231385000036164648264460849230407872181895999905649609776936"
            + "8017749273708962006689187956744210730");
        BigInteger x = new BigInteger("774290984479563168206130828532207106685994961942");
        BigInteger y = new BigInteger(
            "11413953692062257086993806233172330674938775529337393031977771373"
            + "129746946910914240113023221721777732136818444139744393157698465044933"
            + "013442758757568273862367115354816009554808091206304096963365266649829"
            + "966917085474283297375073085459703201287235180005340124397005934806133"
            + "1526243448471205166130497310892424132");

        DSAPublicKeyParameters pk = new DSAPublicKeyParameters(y, new DSAParameters(p, q, g));
        DSAPrivateKeyParameters sk = new DSAPrivateKeyParameters(x, new DSAParameters(p, q, g));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));
        
        DSASigner signer = new DSASigner();

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        // legacy usage allowed for verification.
        signer.init(false, pk);
        
        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test1024bitRSA()
    {
        BigInteger mod = new BigInteger("dbe3d9e35c7b3791e235e9146a5e27be06f202bbd2bc4c772e892b6d613da42cea1f0bffdd45220c1e7e9a21f94b0d86363986238e07d8b28fabde84ed35f1620daef807f27e021be84c7dffecc1106ab414a004a06c410f7cf96c720fbc70a2b357a4edd709ed23c7dc6e6e01433cd8a3e5b49b09ef4f4b6b0086f2fb07b4d9", 16);
        BigInteger pubExp = new BigInteger("10001", 16);
        BigInteger privExp = new BigInteger("2f06cbd29434c5edad335a65c359dfa604563dbf6d9257c8256bb09df3edfaeea02383ad74e514230362901433fc9927daf0f27f282105772ac2d71416a732b820163b22f7e808fa27af5d5e7952ba9f8ecd8e0724469a57bd0d3de828d4953aad0be5ed63ad5b726b012abf5540d4a766b6009124077aac577bcf2ef677531", 16);

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(112, 80));

        RSAKeyParameters pk = new RSAKeyParameters(false, mod, pubExp);
        RSAKeyParameters sk = new RSAKeyParameters(true, mod, privExp);
        RSAEngine rsaEngine = new RSAEngine();

        // signing - fail private key for encryption
        try
        {
            rsaEngine.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 80", e.getMessage());
        }

        // legacy usage allowed for verification.
        rsaEngine.init(false, pk);

        // encryption - fail public key for encryption
        try
        {
            rsaEngine.init(true, pk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 80", e.getMessage());
        }

        // legacy usage allowed for decryption.
        rsaEngine.init(false, sk);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSerpent()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        SerpentEngine engine = new SerpentEngine();

        try
        {
            engine.init(true, new KeyParameter(new byte[12]));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[12]));

        engine.init(true, new KeyParameter(new byte[16]));

        TnepresEngine tengine = new TnepresEngine();

        try
        {
            tengine.init(true, new KeyParameter(new byte[12]));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }

        tengine.init(false, new KeyParameter(new byte[12]));

        tengine.init(true, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testTwofish()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192, 80));

        TwofishEngine engine = new TwofishEngine();

        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        engine.init(true, new KeyParameter(new byte[24]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSkipjack()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        SkipjackEngine engine = new SkipjackEngine();

        try
        {
            engine.init(true, new KeyParameter(new byte[10]));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[10]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testAES()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));
        AESEngine engine = new AESEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }


        engine.init(false, new KeyParameter(new byte[16]));

        engine.init(true, new KeyParameter(new byte[24]));
        engine.init(false, new KeyParameter(new byte[24]));

        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testAESFast()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));

        AESFastEngine engine = new AESFastEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 20", e.getMessage());
        }


        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testAESLight()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));
        AESLightEngine engine = new AESLightEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }


        engine.init(false, new KeyParameter(new byte[16]));

        engine.init(true, new KeyParameter(new byte[24]));
        engine.init(false, new KeyParameter(new byte[24]));

        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testARIA()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));
        AESEngine engine = new AESEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }


        engine.init(false, new KeyParameter(new byte[16]));

        engine.init(true, new KeyParameter(new byte[24]));
        engine.init(false, new KeyParameter(new byte[24]));

        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testMD2()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new MD2Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 64", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testMD4()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new MD4Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 64", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testMD5()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new MD5Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 64", e.getMessage());
        }
        
        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA1()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(128));

        try
        {
            new SHA1Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        new SHA1Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA224()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192));

        try
        {
            new SHA224Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 112", e.getMessage());
        }

        new SHA224Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA256()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(192));

        try
        {
            new SHA256Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 192 bits of security only 128", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA256Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA384()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new SHA384Digest();
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 192", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA384Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA512()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA512Digest();
        new SHA512Digest(CryptoServicePurpose.PRF);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSHA3()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new SHA3Digest(224);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 112", e.getMessage());
        }

        try
        {
            new SHA3Digest(256);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new SHA3Digest(384);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 192", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        new SHA3Digest(256, CryptoServicePurpose.PRF);
        new SHA3Digest(384, CryptoServicePurpose.PRF);

        try
        {
            new SHA3Digest(224, CryptoServicePurpose.PRF);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 192", e.getMessage());
        }

        try
        {
            new SHAKEDigest(128);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new CSHAKEDigest(128, new byte[0], new byte[0]);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new KMAC(128, new byte[0]);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            new SHAKEDigest(128, CryptoServicePurpose.PRF);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        new SHA3Digest(512);
        new SHAKEDigest(256);
        new CSHAKEDigest(256, new byte[0], new byte[0]);
        new KMAC(256, new byte[0]);
        
        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testDSTU7564()
    {
        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            new DSTU7564Digest(256);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }
        try
        {
            new DSTU7564Digest(384);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 192", e.getMessage());
        }
        
        new DSTU7564Digest(512);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }


    public static void main(
         String[] args)
     {
         runTest(new CryptoServiceConstraintsTest());
     }
}
