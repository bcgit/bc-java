package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC2Parameters;
import org.bouncycastle.crypto.params.RC5Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class SymmetricConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "SymmetricConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        testDES();
        testSerpent();
        testTwofish();
        testSkipjack();
        testAES();
        testAESFast();
        testAESLight();
        testARIA();
        testIDEA();
        testCAST5();
        testCAST6();
        testCamelliaLight();
        testCamellia();
        testBlowfish();
        testSM4();
        testTEA();
        testXTEA();
        testThreefish();
        testSalsa20AndXSalsa20AndChaCha();
        testZuc128AndZuc256();
        testVMPCAndVMPCKSA();
        testRC532AndRC564();
        testRijndael();
        testHC128AndHC256();
        testSEED();
        testISAAC();
        testShacal2();
        testGost28147();
        testGost28147Mac();
        testGrain128();
        testGrain128AEAD();
        testGrainv1();
        testDSTU7624();
        testLEA();
        testNoekeon();
        testRC2();
        testRC6();
    }

    private void testDES()
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

        try
        {
            DESKeyGenerator kg = new DESKeyGenerator();

            kg.init(new KeyGenerationParameters(new SecureRandom(), 56));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 56", e.getMessage());
        }

        try
        {
            DESedeKeyGenerator kg = new DESedeKeyGenerator();

            kg.init(new KeyGenerationParameters(new SecureRandom(), 192));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 112", e.getMessage());
        }

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
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));

        AESFastEngine engine = new AESFastEngine();
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
        ARIAEngine engine = new ARIAEngine();
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

    private void testBlowfish()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));
        BlowfishEngine engine = new BlowfishEngine();
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

    private void testCamellia()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256));
        CamelliaEngine engine = new CamelliaEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }


        engine.init(false, new KeyParameter(new byte[16]));

        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testCamelliaLight()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256));
        CamelliaLightEngine engine = new CamelliaLightEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testCAST5()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256));
        CAST5Engine engine = new CAST5Engine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSEED()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256));
        SEEDEngine engine = new SEEDEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testIDEA()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256));
        IDEAEngine engine = new IDEAEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }


        engine.init(false, new KeyParameter(new byte[16]));
        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSM4()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        SM4Engine engine = new SM4Engine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testTEA()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        TEAEngine engine = new TEAEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testXTEA()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        TEAEngine engine = new TEAEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testCAST6()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        CAST6Engine engine = new CAST6Engine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));     // should work

        engine.init(true, new KeyParameter(new byte[32]));      // should work

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testISAAC()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        ISAACEngine engine = new ISAACEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));     // should work

        engine.init(true, new KeyParameter(new byte[32]));      // should work

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testShacal2()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        Shacal2Engine engine = new Shacal2Engine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));     // should work

        engine.init(true, new KeyParameter(new byte[32]));      // should work

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testThreefish()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(384, 256));
        ThreefishEngine engine = new ThreefishEngine(256);
        try
        {
            engine.init(true, new KeyParameter(new byte[32]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 384 bits of security only 256", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testSalsa20AndXSalsa20AndChaCha()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        Salsa20Engine engine = new Salsa20Engine();
        XSalsa20Engine xengine = new XSalsa20Engine();
        ChaChaEngine c1engine = new ChaChaEngine();
        ChaCha7539Engine c2engine = new ChaCha7539Engine();

        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            c1engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        xengine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[24]));
        c2engine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));

        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(384, 256));

        try
        {
            xengine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[24]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 384 bits of security only 256", e.getMessage());
        }

        try
        {
            c2engine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 384 bits of security only 256", e.getMessage());
        }

        xengine.init(false, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[24]));
        c2engine.init(false, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testZuc128AndZuc256()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        Zuc128Engine engine = new Zuc128Engine();
        Zuc256Engine xengine = new Zuc256Engine();
        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        xengine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[25]));

        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testVMPCAndVMPCKSA()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        VMPCEngine engine = new VMPCEngine();
        VMPCKSA3Engine xengine = new VMPCKSA3Engine();
        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        xengine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[25]));

        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testRC532AndRC564()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        RC532Engine engine = new RC532Engine();
        RC564Engine xengine = new RC564Engine();
        try
        {
            engine.init(true, new RC5Parameters(new byte[16], 16));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        xengine.init(true, new RC5Parameters(new byte[32], 12));

        engine.init(false, new RC5Parameters(new byte[16], 16));
        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testRijndael()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        RijndaelEngine engine = new RijndaelEngine(256);
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testHC128AndHC256()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        HC256Engine engine = new HC256Engine();
        HC128Engine xengine = new HC128Engine();
        try
        {
            xengine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        xengine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        engine.init(true, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[32]));
        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[32]), new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testGost28147()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        GOST28147Engine engine = new GOST28147Engine();
        try
        {
            engine.init(true, new KeyParameter(new byte[32]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 178", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testGost28147Mac()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        GOST28147Mac engine = new GOST28147Mac();
        try
        {
            engine.init(new KeyParameter(new byte[32]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 178", e.getMessage());
        }

        engine = new GOST28147Mac(CryptoServicePurpose.VERIFICATION);
        engine.init(new KeyParameter(new byte[32]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testGrain128()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        Grain128Engine engine = new Grain128Engine();
        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testGrain128AEAD()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        Grain128AEADEngine engine = new Grain128AEADEngine();
        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testGrainv1()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 80));
        Grainv1Engine engine = new Grainv1Engine();
        try
        {
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[8]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 80", e.getMessage());
        }

        engine.init(false, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[8]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testDSTU7624()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));
        DSTU7624Engine engine = new DSTU7624Engine(128);
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

        engine.init(true, new KeyParameter(new byte[32]));
        engine.init(false, new KeyParameter(new byte[32]));

        engine = new DSTU7624Engine(256);

        engine.init(true, new KeyParameter(new byte[64]));
        engine.init(false, new KeyParameter(new byte[64]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testLEA()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(192));
        LEAEngine engine = new LEAEngine();
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

    private void testNoekeon()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        NoekeonEngine engine = new NoekeonEngine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testRC2()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        RC2Engine engine = new RC2Engine();
        try
        {
            engine.init(true, new RC2Parameters(new byte[16], 16));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new RC2Parameters(new byte[16], 16));
        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testRC6()
    {
        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        RC6Engine engine = new RC6Engine();
        try
        {
            engine.init(true, new KeyParameter(new byte[16]));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        engine.init(false, new KeyParameter(new byte[16]));

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public static void main(
        String[] args)
    {
        runTest(new SymmetricConstraintsTest());
    }
}
