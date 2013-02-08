package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHKeyParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.GOST3410ValidationParameters;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;
import java.security.SecureRandom;

class DHTestKeyParameters
    extends DHKeyParameters
{
    protected DHTestKeyParameters(boolean isPrivate, DHParameters params)
    {
        super(isPrivate, params);
    }
}

class ElGamalTestKeyParameters
    extends ElGamalKeyParameters
{
    protected ElGamalTestKeyParameters(boolean isPrivate, ElGamalParameters params)
    {
        super(isPrivate, params);
    }
}

public class EqualsHashCodeTest
        extends SimpleTest
{
    private static Object OTHER = new Object();

    public String getName()
    {
        return "EqualsHashCode";
    }

    private void doTest(Object a, Object equalsA, Object notEqualsA)
    {
        if (a.equals(null))
        {
            fail("a equaled null");
        }

        if (!a.equals(equalsA) || !equalsA.equals(a))
        {
            fail("equality failed");
        }

        if (a.equals(OTHER))
        {
            fail("other inequality failed");
        }

        if (a.equals(notEqualsA) || notEqualsA.equals(a))
        {
            fail("inequality failed");
        }

        if (a.hashCode() != equalsA.hashCode())
        {
            fail("hashCode equality failed");
        }
    }

    private void dhTest()
    {
        BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        DHParameters                dhParams = new DHParameters(p512, g512);
        DHKeyGenerationParameters   params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);         DHKeyPairGenerator          kpGen = new DHKeyPairGenerator();

        kpGen.init(params);

        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();
        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();

        DHPublicKeyParameters       pu2 = new DHPublicKeyParameters(pu1.getY(), pu1.getParameters());
        DHPrivateKeyParameters      pv2 = new DHPrivateKeyParameters(pv1.getX(), pv1.getParameters());
        DHPublicKeyParameters       pu3 = new DHPublicKeyParameters(pv1.getX(), pu1.getParameters());
        DHPrivateKeyParameters      pv3 = new DHPrivateKeyParameters(pu1.getY(), pu1.getParameters());

        doTest(pu1, pu2, pu3);
        doTest(pv1, pv2, pv3);

        DHParameters                pr1 = pu1.getParameters();
        DHParameters                pr2 = new DHParameters(pr1.getP(), pr1.getG(), pr1.getQ(), pr1.getM(), pr1.getL(), pr1.getJ(), pr1.getValidationParameters());
        DHParameters                pr3 = new DHParameters(pr1.getG(), pr1.getP(), pr1.getQ(), pr1.getM(), pr1.getL(), pr1.getJ(), pr1.getValidationParameters());

        doTest(pr1, pr2, pr3);

        pr3 = new DHParameters(pr1.getG(), pr1.getP(), null, pr1.getM(), pr1.getL(), pr1.getJ(), pr1.getValidationParameters());

        doTest(pr1, pr2, pr3);        

        pu2 = new DHPublicKeyParameters(pu1.getY(), pr2);
        pv2 = new DHPrivateKeyParameters(pv1.getX(), pr2);

        doTest(pu1, pu2, pu3);
        doTest(pv1, pv2, pv3);

        DHValidationParameters vp1 = new DHValidationParameters(new byte[20], 1024);
        DHValidationParameters vp2 = new DHValidationParameters(new byte[20], 1024);
        DHValidationParameters vp3 = new DHValidationParameters(new byte[24], 1024);

        doTest(vp1, vp1, vp3);
        doTest(vp1, vp2, vp3);

        byte[] bytes = new byte[20];
        bytes[0] = 1;

        vp3 = new DHValidationParameters(bytes, 1024);

        doTest(vp1, vp2, vp3);

        vp3 = new DHValidationParameters(new byte[20], 2048);

        doTest(vp1, vp2, vp3);

        DHTestKeyParameters k1 = new DHTestKeyParameters(false, null);
        DHTestKeyParameters k2 = new DHTestKeyParameters(false, null);
        DHTestKeyParameters k3 = new DHTestKeyParameters(false, pu1.getParameters());

        doTest(k1, k2, k3);
    }

    private void elGamalTest()
    {
        BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        ElGamalParameters dhParams = new ElGamalParameters(p512, g512);
        ElGamalKeyGenerationParameters params = new ElGamalKeyGenerationParameters(new SecureRandom(), dhParams);         ElGamalKeyPairGenerator kpGen = new ElGamalKeyPairGenerator();

        kpGen.init(params);

        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();
        ElGamalPublicKeyParameters       pu1 = (ElGamalPublicKeyParameters)pair.getPublic();
        ElGamalPrivateKeyParameters      pv1 = (ElGamalPrivateKeyParameters)pair.getPrivate();

        ElGamalPublicKeyParameters       pu2 = new ElGamalPublicKeyParameters(pu1.getY(), pu1.getParameters());
        ElGamalPrivateKeyParameters      pv2 = new ElGamalPrivateKeyParameters(pv1.getX(), pv1.getParameters());
        ElGamalPublicKeyParameters       pu3 = new ElGamalPublicKeyParameters(pv1.getX(), pu1.getParameters());
        ElGamalPrivateKeyParameters      pv3 = new ElGamalPrivateKeyParameters(pu1.getY(), pu1.getParameters());

        doTest(pu1, pu2, pu3);
        doTest(pv1, pv2, pv3);

        ElGamalParameters                pr1 = pu1.getParameters();
        ElGamalParameters                pr2 = new ElGamalParameters(pr1.getP(), pr1.getG());
        ElGamalParameters                pr3 = new ElGamalParameters(pr1.getG(), pr1.getP());

        doTest(pr1, pr2, pr3);

        pu2 = new ElGamalPublicKeyParameters(pu1.getY(), pr2);
        pv2 = new ElGamalPrivateKeyParameters(pv1.getX(), pr2);

        doTest(pu1, pu2, pu3);
        doTest(pv1, pv2, pv3);

        ElGamalTestKeyParameters k1 = new ElGamalTestKeyParameters(false, null);
        ElGamalTestKeyParameters k2 = new ElGamalTestKeyParameters(false, null);
        ElGamalTestKeyParameters k3 = new ElGamalTestKeyParameters(false, pu1.getParameters());

        doTest(k1, k2, k3);
    }

    private void dsaTest()
    {
        BigInteger a = BigInteger.valueOf(1), b = BigInteger.valueOf(2), c = BigInteger.valueOf(3);

        DSAParameters dsaP1 = new DSAParameters(a, b, c);
        DSAParameters dsaP2 = new DSAParameters(a, b, c);
        DSAParameters dsaP3 = new DSAParameters(b, c, a);

        doTest(dsaP1, dsaP2, dsaP3);

        DSAValidationParameters vp1 = new DSAValidationParameters(new byte[20], 1024);
        DSAValidationParameters vp2 = new DSAValidationParameters(new byte[20], 1024);
        DSAValidationParameters vp3 = new DSAValidationParameters(new byte[24], 1024);

        doTest(vp1, vp1, vp3);
        doTest(vp1, vp2, vp3);

        byte[] bytes = new byte[20];
        bytes[0] = 1;

        vp3 = new DSAValidationParameters(bytes, 1024);

        doTest(vp1, vp2, vp3);

        vp3 = new DSAValidationParameters(new byte[20], 2048);

        doTest(vp1, vp2, vp3);
    }

    private void gost3410Test()
    {
        BigInteger a = BigInteger.valueOf(1), b = BigInteger.valueOf(2), c = BigInteger.valueOf(3);

        GOST3410Parameters g1 = new GOST3410Parameters(a, b, c);
        GOST3410Parameters g2 = new GOST3410Parameters(a, b, c);
        GOST3410Parameters g3 = new GOST3410Parameters(a, c, c);

        doTest(g1, g2, g3);

        GOST3410ValidationParameters v1 = new GOST3410ValidationParameters(100, 1);
        GOST3410ValidationParameters v2 = new GOST3410ValidationParameters(100, 1);
        GOST3410ValidationParameters v3 = new GOST3410ValidationParameters(101, 1);

        doTest(v1, v2, v3);

        v3 = new GOST3410ValidationParameters(100, 2);

        doTest(v1, v2, v3);

        v1 = new GOST3410ValidationParameters(100L, 1L);
        v2 = new GOST3410ValidationParameters(100L, 1L);
        v3 = new GOST3410ValidationParameters(101L, 1L);

        doTest(v1, v2, v3);

        v3 = new GOST3410ValidationParameters(100L, 2L);

        doTest(v1, v2, v3);

    }

    public void performTest()
        throws Exception
    {
        dhTest();
        elGamalTest();
        gost3410Test();
        dsaTest();
    }

    public static void main(
        String[]    args)
    {
        runTest(new EqualsHashCodeTest());
    }
}
