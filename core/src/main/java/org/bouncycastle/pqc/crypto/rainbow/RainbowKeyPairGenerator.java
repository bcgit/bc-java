package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class RainbowKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private RainbowKeyComputation rkc;
    private Version version;

    private void initialize(KeyGenerationParameters param)
    {
        RainbowParameters rainbowParams = ((RainbowKeyGenerationParameters)param).getParameters();
        this.rkc = new RainbowKeyComputation(rainbowParams, param.getRandom());
        this.version = rainbowParams.getVersion();
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        switch (this.version)
        {
        case CLASSIC:
            return this.rkc.genKeyPairClassical();
        case CIRCUMZENITHAL:
            return this.rkc.genKeyPairCircumzenithal();
        case COMPRESSED:
            return this.rkc.genKeyPairCompressed();
        default:
            throw new IllegalArgumentException(
                "No valid version. Please choose one of the following: classic, circumzenithal, compressed");
        }
    }
}
