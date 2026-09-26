package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.ECVKOAgreement;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.engines.CryptoProWrapEngine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.GOST28147WrapEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * {@link ParametersWithUKM} goes outside {@link ParametersWithRandom} (see the
 * {@code org.bouncycastle.crypto.params} package documentation). Every UKM consumer must accept that
 * nesting with the same result as no random at all, and the GOST 28147 wrap engines must also still
 * accept the earlier {@code Random(UKM(..))}.
 */
public class UKMParametersNestingTest
    extends SimpleTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] KEK = Hex.decode("8b2f3a41c6d5e7091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081");
    private static final byte[] CEK = Hex.decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    private static final byte[] UKM = Hex.decode("1d80603c8544c727");

    public String getName()
    {
        return "UKMParametersNesting";
    }

    public void performTest()
        throws Exception
    {
        wrapTest("GOST28147Wrap", new GOST28147WrapEngine(), null);
        wrapTest("GOST28147Wrap/SBox", new GOST28147WrapEngine(), GOST28147Engine.getSBox("E-A"));
        wrapTest("CryptoProWrap", new CryptoProWrapEngine(), null);
        wrapTest("CryptoProWrap/SBox", new CryptoProWrapEngine(), GOST28147Engine.getSBox("E-A"));

        vkoTest();
    }

    private void wrapTest(String label, Wrapper wrapper, byte[] sBox)
        throws Exception
    {
        byte[] expected = null;

        for (int i = 0; i < 3; ++i)
        {
            wrapper.init(true, createWrapParameters(i, sBox));
            byte[] wrapped = wrapper.wrap(CEK, 0, CEK.length);
            if (expected == null)
            {
                expected = wrapped;
            }
            isTrue(label + " wrap differs for nesting " + i, areEqual(expected, wrapped));

            wrapper.init(false, createWrapParameters(i, sBox));
            byte[] unwrapped = wrapper.unwrap(expected, 0, expected.length);
            isTrue(label + " unwrap differs for nesting " + i, areEqual(CEK, unwrapped));
        }
    }

    private static CipherParameters createWrapParameters(int nesting, byte[] sBox)
    {
        CipherParameters key = new KeyParameter(KEK);
        if (sBox != null)
        {
            key = new ParametersWithSBox(key, sBox);
        }

        switch (nesting)
        {
        case 0:
            return new ParametersWithUKM(key, UKM);
        case 1:
            return new ParametersWithUKM(new ParametersWithRandom(key, RANDOM), UKM);
        case 2:
            return new ParametersWithRandom(new ParametersWithUKM(key, UKM), RANDOM);
        default:
            throw new IllegalArgumentException("nesting");
        }
    }

    private void vkoTest()
    {
        ECDomainParameters domain = new ECDomainParameters(
            ECGOST3410NamedCurves.getByNameX9("Tc26-Gost-3410-12-256-paramSetA"));

        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();
        kpGen.init(new ECKeyGenerationParameters(domain, RANDOM));

        AsymmetricCipherKeyPair kpA = kpGen.generateKeyPair();
        AsymmetricCipherKeyPair kpB = kpGen.generateKeyPair();

        ECVKOAgreement agreeA = new ECVKOAgreement(new GOST3411_2012_256Digest());
        agreeA.init(new ParametersWithUKM(kpA.getPrivate(), UKM));
        byte[] expected = agreeA.calculateAgreement(kpB.getPublic());

        agreeA.init(new ParametersWithUKM(new ParametersWithRandom(kpA.getPrivate(), RANDOM), UKM));
        isTrue("VKO agreement differs for UKM(Random(key))", areEqual(expected, agreeA.calculateAgreement(kpB.getPublic())));

        ECVKOAgreement agreeB = new ECVKOAgreement(new GOST3411_2012_256Digest());
        agreeB.init(new ParametersWithUKM(new ParametersWithRandom(kpB.getPrivate(), RANDOM), UKM));
        isTrue("VKO peer agreement differs for UKM(Random(key))", areEqual(expected, agreeB.calculateAgreement(kpA.getPublic())));
    }

    public static void main(String[] args)
    {
        runTest(new UKMParametersNestingTest());
    }
}
