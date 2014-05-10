package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ElGamalTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    private BigInteger yPgpBogusPSamp = new BigInteger("de4688497cc05b45fe8559bc9918c45afcad69b74123a7236eba409fd9de8ea34c7869839ee9df35e3d97576145d089841aa65b5b4e061fae52c37e430354269a02496b8ed8456f2d0d7c9b0db985fbcb21ae9f78507ed6e3a29db595b201b1a4f931c7d791eede65ccf918e8a61cf146859151c78c41ad48853694623467d78", 16);
    private BigInteger xPgpBogusPSamp = new BigInteger("cbaf780f2cfe4f987bbc5fcb0738bbd7912060ccfdf37cbfeea65c0fd857e74a8df6cc359375f28cf5725d081813c614410a78cbe4b06d677beea9ff0fa10b1dbc47a6ed8c5b8466d6a95d6574029dbdf72596392e1b6b230faf9916dc8455821c10527a375a4d1c8a54947d1fe714d321aca25ad486b4b456506999fd2fd11a", 16);
    private BigInteger gPgpBogusPSamp = new BigInteger("153ffe9522076d1cbd6e75f0816a0fc2ebd8b0e0091406587387a1763022088a03b411eed07ff50efb82b21f1608c352d10f63ba7e7e981a2f3387cec8af2915953d00493857663ae8919f517fe90f1d2abe7af4305a344b10d1a25d75f65902cd7fd775853d3ac43d7c5253ad666e1e63ee98cdcb10af81273d4ff053ff07d51", 16);
    private BigInteger pPgpBogusPSamp = new BigInteger("15061b26cdab4e865098a01c86f13b03220104c5443e950658b36b85245aa0c616a0c0d8d99c454bea087c172315e45b3bc9b925443948a2b6ba47608a6035b9a79a4ef34a78d7274a12ede8364f02d5030db864988643d7e92753df603bd69fbd2682ab0af64d1a866d1131a2cb13333cedb0a9e6eefddd9fff8154d34c2daab", 16);
    private int lPgpBogusPSamp = 0;

    public String getName()
    {
        return "ElGamal";
    }

    private void testEnc(
        int         size,
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
    {
        ElGamalParameters                dhParams = new ElGamalParameters(p, g, privateValueSize);
        ElGamalKeyGenerationParameters   params = new ElGamalKeyGenerationParameters(new SecureRandom(), dhParams);
        ElGamalKeyPairGenerator          kpGen = new ElGamalKeyPairGenerator();

        kpGen.init(params);

        //
        // generate pair
        //
        AsymmetricCipherKeyPair         pair = kpGen.generateKeyPair();

        ElGamalPublicKeyParameters      pu = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters     pv = (ElGamalPrivateKeyParameters)pair.getPrivate();

        checkKeySize(privateValueSize, pv);

        ElGamalEngine    e = new ElGamalEngine();

        e.init(true, pu);
        
        if (e.getOutputBlockSize() != size / 4)
        {
            fail(size + " getOutputBlockSize() on encryption failed.");
        }

        byte[]  message = Hex.decode("5468697320697320612074657374");

        byte[]  pText = message;
        byte[]  cText = e.processBlock(pText, 0, pText.length);

        e.init(false, pv);

        if (e.getOutputBlockSize() != (size / 8) - 1)
        {
            fail(size + " getOutputBlockSize() on decryption failed.");
        }
        
        pText = e.processBlock(cText, 0, cText.length);

        if (!Arrays.areEqual(message, pText))
        {
            fail(size + " bit test failed");
        }
        
        e.init(true, pu);

        byte[] bytes = new byte[e.getInputBlockSize() + 2];
        
        try
        {
            e.processBlock(bytes, 0, bytes.length);
            
            fail("out of range block not detected");
        }
        catch (DataLengthException ex)
        {
            // expected
        }
        
        try
        {
            bytes[0] = (byte)0xff;
            
            e.processBlock(bytes, 0, bytes.length - 1);
            
            fail("out of range block not detected");
        }
        catch (DataLengthException ex)
        {
            // expected
        }
        
        try
        {
            bytes[0] = (byte)0x7f;

            e.processBlock(bytes, 0, bytes.length - 1);
        }
        catch (DataLengthException ex)
        {
            fail("in range block failed");
        }

        try
        {
            bytes = BigIntegers.asUnsignedByteArray(p);

            e.processBlock(bytes, 0, bytes.length);

            fail("out of range block not detected");
        }
        catch (DataLengthException ex)
        {
            // expected
        }

        try
        {
            bytes = BigIntegers.asUnsignedByteArray(p.subtract(BigInteger.valueOf(1)));

            e.processBlock(bytes, 0, bytes.length);
        }
        catch (DataLengthException ex)
        {
            fail("boundary block rejected");
        }
    }

    private void checkKeySize(
        int privateValueSize,
        ElGamalPrivateKeyParameters priv)
    {
        if (privateValueSize != 0)
        {
            if (priv.getX().bitLength() != privateValueSize)
            {
                fail("limited key check failed for key size " + privateValueSize);
            }
        }
    }

    /**
     * this test is can take quiet a while
     *
     * @param size size of key in bits.
     */
    private void testGeneration(
        int         size)
    {
        ElGamalParametersGenerator       pGen = new ElGamalParametersGenerator();

        pGen.init(size, 10, new SecureRandom());

        ElGamalParameters                elParams = pGen.generateParameters();

        if (elParams.getL() != 0)
        {
            fail("ElGamalParametersGenerator failed to set L to 0 in generated ElGamalParameters");
        }

        ElGamalKeyGenerationParameters   params = new ElGamalKeyGenerationParameters(new SecureRandom(), elParams);

        ElGamalKeyPairGenerator          kpGen = new ElGamalKeyPairGenerator();

        kpGen.init(params);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair         pair = kpGen.generateKeyPair();

        ElGamalPublicKeyParameters      pu = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters     pv = (ElGamalPrivateKeyParameters)pair.getPrivate();

        ElGamalEngine    e = new ElGamalEngine();

        e.init(true, new ParametersWithRandom(pu, new SecureRandom()));

        byte[]  message = Hex.decode("5468697320697320612074657374");

        byte[]  pText = message;
        byte[]  cText = e.processBlock(pText, 0, pText.length);

        e.init(false, pv);

        pText = e.processBlock(cText, 0, cText.length);

        if (!Arrays.areEqual(message, pText))
        {
            fail("generation test failed");
        }
    }

    private void testInitCheck()
    {
        try
        {
            new ElGamalEngine().processBlock(new byte[]{ 1 }, 0, 1);
            fail("failed initialisation check");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
    }

    private void testInvalidP()
    {
        ElGamalParameters               dhParams = new ElGamalParameters(pPgpBogusPSamp, gPgpBogusPSamp, lPgpBogusPSamp);
        ElGamalPublicKeyParameters      pu = new ElGamalPublicKeyParameters(yPgpBogusPSamp, dhParams);
        ElGamalPrivateKeyParameters     pv = new ElGamalPrivateKeyParameters(xPgpBogusPSamp, dhParams);

        ElGamalEngine    e = new ElGamalEngine();

        e.init(true, pu);

        byte[]  message = Hex.decode("5468697320697320612074657374");

        byte[]  pText = message;
        byte[]  cText = e.processBlock(pText, 0, pText.length);

        e.init(false, pv);

        pText = e.processBlock(cText, 0, cText.length);

        if (Arrays.areEqual(message, pText))
        {
            fail("invalid test failed");
        }
    }

    public void performTest()
    {
        testInvalidP();

        testEnc(512, 0, g512, p512);
        testEnc(768, 0, g768, p768);
        testEnc(1024, 0, g1024, p1024);

        testEnc(512, 64, g512, p512);
        testEnc(768, 128, g768, p768);

        //
        // generation test.
        //
        testGeneration(258);

        testInitCheck();
    }

    public static void main(
        String[]    args)
    {
        runTest(new ElGamalTest());
    }
}
