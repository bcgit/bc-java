package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.CryptoProWrapEngine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * {@link CryptoProWrapEngine} (RFC 4357 sec. 6.3, with the sec. 6.5 KEK diversification) given no
 * S-box uses the GOST 28147 engine's default one throughout, and never modifies the caller's key.
 */
public class CryptoProWrapEngineTest
    extends SimpleTest
{
    private static final byte[] KEK = Hex.decode("8b2f3a41c6d5e7091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081");
    private static final byte[] CEK = Hex.decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    private static final byte[] UKM = Hex.decode("1d80603c8544c727");

    public String getName()
    {
        return "CryptoProWrapEngine";
    }

    public void performTest()
        throws Exception
    {
        defaultSBoxTest();

        keyUnmodifiedTest(null);
        keyUnmodifiedTest(GOST28147Engine.getSBox("E-A"));
    }

    private void defaultSBoxTest()
        throws Exception
    {
        CryptoProWrapEngine engine = new CryptoProWrapEngine();

        engine.init(true, new ParametersWithUKM(
            new ParametersWithSBox(new KeyParameter(KEK), GOST28147Engine.getSBox("Default")), UKM));
        byte[] expected = engine.wrap(CEK, 0, CEK.length);

        engine.init(true, new ParametersWithUKM(new KeyParameter(KEK), UKM));
        isTrue("no S-box wrap differs from the default S-box", areEqual(expected, engine.wrap(CEK, 0, CEK.length)));

        engine.init(false, new ParametersWithUKM(new KeyParameter(KEK), UKM));
        isTrue("no S-box unwrap failed", areEqual(CEK, engine.unwrap(expected, 0, expected.length)));
    }

    private void keyUnmodifiedTest(byte[] sBox)
        throws Exception
    {
        String label = sBox == null ? "no S-box" : "S-box";

        KeyParameter key = new KeyParameter(KEK);
        CipherParameters kParam = key;
        if (sBox != null)
        {
            kParam = new ParametersWithSBox(kParam, sBox);
        }
        ParametersWithUKM params = new ParametersWithUKM(kParam, UKM);

        CryptoProWrapEngine engine = new CryptoProWrapEngine();

        engine.init(true, params);
        byte[] wrapped = engine.wrap(CEK, 0, CEK.length);
        isTrue(label + ": caller's key modified by init", areEqual(KEK, key.getKey()));

        engine.init(true, params);
        isTrue(label + ": wrap differs on re-init with the same parameters",
            areEqual(wrapped, engine.wrap(CEK, 0, CEK.length)));

        engine.init(false, params);
        isTrue(label + ": unwrap with the same parameters failed", areEqual(CEK, engine.unwrap(wrapped, 0, wrapped.length)));
        isTrue(label + ": caller's key modified by re-init", areEqual(KEK, key.getKey()));
    }

    public static void main(String[] args)
    {
        runTest(new CryptoProWrapEngineTest());
    }
}
