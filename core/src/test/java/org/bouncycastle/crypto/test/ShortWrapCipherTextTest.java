package org.bouncycastle.crypto.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.DESedeWrapEngine;
import org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
import org.bouncycastle.crypto.engines.GOST28147WrapEngine;
import org.bouncycastle.crypto.engines.RC2WrapEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.crypto.params.RC2Parameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

/**
 * A ciphertext / wrapped-key shorter than the fixed overhead the engine strips
 * must be rejected with an {@link InvalidCipherTextException}, not an escaping
 * {@code NegativeArraySizeException} / {@code ArrayIndexOutOfBoundsException}
 * from the {@code new byte[inLen - overhead]} allocation.
 */
public class ShortWrapCipherTextTest
    extends SimpleTest
{
    public String getName()
    {
        return "ShortWrapCipherText";
    }

    private void sm2()
        throws Exception
    {
        BigInteger p = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger a = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger b = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger n = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger gx = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger gy = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

        ECCurve curve = new ECCurve.Fp(p, a, b, n, ECConstants.ONE);
        ECPoint g = curve.createPoint(gx, gy);
        ECDomainParameters domainParams = new ECDomainParameters(curve, g, n);

        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16)));
        AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

        SM2Engine engine = new SM2Engine();
        engine.init(false, (ECPrivateKeyParameters)kp.getPrivate());

        // C1 (65) + C3 (32) is 97 octets; anything shorter cannot hold C1 + digest.
        try
        {
            engine.processBlock(new byte[50], 0, 50);
            fail("SM2Engine: no exception on short ciphertext");
        }
        catch (InvalidCipherTextException e)
        {
            isEquals("ciphertext too short", e.getMessage());
        }
    }

    private void gost28147Wrap()
        throws Exception
    {
        GOST28147WrapEngine engine = new GOST28147WrapEngine();
        engine.init(false, new ParametersWithUKM(new KeyParameter(new byte[32]), new byte[8]));

        try
        {
            engine.unwrap(new byte[16], 0, 16);
            fail("GOST28147WrapEngine: no exception on short input");
        }
        catch (InvalidCipherTextException e)
        {
            isEquals("unwrap data too short", e.getMessage());
        }
    }

    private void dstu7624Wrap()
        throws Exception
    {
        DSTU7624WrapEngine engine = new DSTU7624WrapEngine(128);
        engine.init(false, new KeyParameter(new byte[16]));

        try
        {
            engine.unwrap(new byte[0], 0, 0);
            fail("DSTU7624WrapEngine: no exception on empty input");
        }
        catch (InvalidCipherTextException e)
        {
            isEquals("unwrap data too short", e.getMessage());
        }
    }

    private void desedeWrap()
        throws Exception
    {
        DESedeWrapEngine engine = new DESedeWrapEngine();
        engine.init(false, new KeyParameter(Hex.decode("0123456789abcdeffedcba987654321089abcdef01234567")));

        try
        {
            engine.unwrap(new byte[8], 0, 8);
            fail("DESedeWrapEngine: no exception on short input");
        }
        catch (InvalidCipherTextException e)
        {
            isEquals("unwrap data too short", e.getMessage());
        }
    }

    private void rc2Wrap()
        throws Exception
    {
        RC2WrapEngine engine = new RC2WrapEngine();
        engine.init(false, new RC2Parameters(new byte[16]));

        try
        {
            engine.unwrap(new byte[8], 0, 8);
            fail("RC2WrapEngine: no exception on short input");
        }
        catch (InvalidCipherTextException e)
        {
            isEquals("unwrap data too short", e.getMessage());
        }
    }

    public void performTest()
        throws Exception
    {
        sm2();
        gost28147Wrap();
        dstu7624Wrap();
        desedeWrap();
        rc2Wrap();
    }

    public static void main(String[] args)
    {
        runTest(new ShortWrapCipherTextTest());
    }
}
