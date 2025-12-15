package org.bouncycastle.pqc.crypto.ntruplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class NTRUPlusKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private NTRUPlusParameters params;
    private SecureRandom random;

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.params = ((NTRUPlusKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        byte[] pk = new byte[params.getPublicKeyBytes()];
        byte[] sk = new byte[params.getSecretKeyBytes()];
        NTRUPlusEngine engine = new NTRUPlusEngine(params);
        byte[] coins = new byte[params.getSymBytes()]; // NTRUPLUS_SYMBYTES

        int n = params.getN();
        // Create polynomial objects
        NTRUPlusEngine.Poly f = new NTRUPlusEngine.Poly(n);
        NTRUPlusEngine.Poly finv = new NTRUPlusEngine.Poly(n);
        NTRUPlusEngine.Poly g = new NTRUPlusEngine.Poly(n);
        NTRUPlusEngine.Poly ginv = new NTRUPlusEngine.Poly(n);

        // Generate f and finv (retry if f is not invertible)
        boolean fInvertible;
        do
        {
            // Generate random bytes for the seed
            random.nextBytes(coins);
            fInvertible = (engine.genf_derand(f, finv, coins) == 0);
        }
        while (!fInvertible);

        // Generate g and ginv (retry if g is not invertible)
        boolean gInvertible;
        do
        {
            // Generate new random bytes for the seed
            random.nextBytes(coins);
            gInvertible = (engine.geng_derand(g, ginv, coins) == 0);
        }
        while (!gInvertible);

        // Generate the actual key pair using the derived polynomials
        engine.crypto_kem_keypair_derand(pk, sk, f, finv, g, ginv);
        return new AsymmetricCipherKeyPair(new NTRUPlusPublicKeyParameters(params, pk), new NTRUPlusPrivateKeyParameters(params, sk));
    }
}
