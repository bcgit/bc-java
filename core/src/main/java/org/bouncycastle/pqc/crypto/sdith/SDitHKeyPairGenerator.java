package org.bouncycastle.pqc.crypto.sdith;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.Arrays;

public class SDitHKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SDitHParameters parameters;
    private SecureRandom random;

    public void init(KeyGenerationParameters param)
    {
        SDitHKeyGenerationParameters p = (SDitHKeyGenerationParameters)param;
        this.parameters = p.getParameters();
        this.random = p.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        SDitHEngine engine = new SDitHEngine(parameters, random);
        byte[][] kp = parameters.getVariant() == SDitHParameters.VARIANT_THRESHOLD
                ? engine.generateKeyPairThreshold()
                : engine.generateKeyPair();
        byte[] pkBytes = kp[0];
        byte[] skBytes = kp[1];
        byte[] mSeed = kp[2];

        int seedSize = parameters.getSeedSize();
        int ySize = parameters.getYSize();
        int k = parameters.getK();
        int qp = parameters.getD() * parameters.getWd();

        byte[] hASeed = Arrays.copyOfRange(skBytes, 0, seedSize);
        byte[] y = Arrays.copyOfRange(skBytes, seedSize, seedSize + ySize);
        byte[] sA = Arrays.copyOfRange(skBytes, seedSize + ySize, seedSize + ySize + k);
        byte[] qPoly = Arrays.copyOfRange(skBytes, seedSize + ySize + k, seedSize + ySize + k + qp);
        byte[] pPoly = Arrays.copyOfRange(skBytes, seedSize + ySize + k + qp, seedSize + ySize + k + 2 * qp);

        SDitHPublicKeyParameters pub = new SDitHPublicKeyParameters(parameters, pkBytes);
        SDitHPrivateKeyParameters priv = new SDitHPrivateKeyParameters(parameters, mSeed, hASeed, y, sA, qPoly, pPoly);

        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
