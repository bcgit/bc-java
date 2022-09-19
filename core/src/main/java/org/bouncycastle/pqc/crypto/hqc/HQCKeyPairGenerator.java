package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class HQCKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private int n;

    private int k;

    private int delta;

    private int w;

    private int wr;

    private int we;
    private int N_BYTE;
    private HQCKeyGenerationParameters hqcKeyGenerationParameters;

    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters params)
    {
        this.hqcKeyGenerationParameters = (HQCKeyGenerationParameters)params;
        this.random = params.getRandom();

        // get parameters
        this.n = this.hqcKeyGenerationParameters.getParameters().getN();
        this.k = this.hqcKeyGenerationParameters.getParameters().getK();
        this.delta = this.hqcKeyGenerationParameters.getParameters().getDelta();
        this.w = this.hqcKeyGenerationParameters.getParameters().getW();
        this.wr = this.hqcKeyGenerationParameters.getParameters().getWr();
        this.we = this.hqcKeyGenerationParameters.getParameters().getWe();
        this.N_BYTE = (n + 7) / 8;
    }

    private AsymmetricCipherKeyPair genKeyPair(byte[] seed)
    {
        HQCEngine engine = hqcKeyGenerationParameters.getParameters().getEngine();
        byte[] pk = new byte[40 + N_BYTE];
        byte[] sk = new byte[40 + 40 + N_BYTE];

        engine.genKeyPair(pk, sk, seed);

        // form keys
        HQCPublicKeyParameters publicKey = new HQCPublicKeyParameters(hqcKeyGenerationParameters.getParameters(), pk);
        HQCPrivateKeyParameters privateKey = new HQCPrivateKeyParameters(hqcKeyGenerationParameters.getParameters(), sk);

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] seed = new byte[48];

        random.nextBytes(seed);

        return genKeyPair(seed);
    }

    public AsymmetricCipherKeyPair generateKeyPairWithSeed(byte[] seed)
    {
        return genKeyPair(seed);
    }
}
