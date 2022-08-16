package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.Arrays;

public class NTRULPRimeKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private NTRULPRimeKeyGenerationParameters params;

    public NTRULPRimeKeyGenerationParameters getParams()
    {
        return params;
    }

    /**
     * intialise the key pair generator.
     *
     * @param param the parameters the key pair is to be initialised with.
     */
    @Override
    public void init(KeyGenerationParameters param)
    {
        this.params = (NTRULPRimeKeyGenerationParameters) param;
    }

    /**
     * return an AsymmetricCipherKeyPair containing the generated keys.
     *
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int p = params.getNtrulprParams().getP();
        int q = params.getNtrulprParams().getQ();
        int w = params.getNtrulprParams().getW();

        /*
         * Generate uniform Random seed
         * Generate G = Generate(seeds) which is in R/q
         */
        byte[] seed = new byte[32];
        params.getRandom().nextBytes(seed);
        short[] G = new short[p];
        Utils.generatePolynomialInRQFromSeed(G, seed, p, q);

        /*
         * Get Random Short Polynomial a in R/q
         * Compute aG
         * Compute A = Round(aG)
         */
        byte[] a = new byte[p];
        Utils.getRandomShortPolynomial(params.getRandom(), a, p, w);
        short[] aG = new short[p];
        Utils.multiplicationInRQ(aG, G, a, p, q);
        short[] A = new short[p];
        Utils.roundPolynomial(A, aG);

        /*
         * Public Key = seed | Encode(A)
         */
        byte[] roundEncA = new byte[params.getNtrulprParams().getPublicKeyBytes() - 32];
        Utils.getRoundedEncodedPolynomial(roundEncA, A, p, q);
        NTRULPRimePublicKeyParameters publicKey = new NTRULPRimePublicKeyParameters(params.getNtrulprParams(), seed, roundEncA);

        /*
         * Private Key = Encode(a) | pk | Random rho | SHA-512(4|pk)
         */
        byte[] enca = new byte[(p + 3) / 4];
        Utils.getEncodedSmallPolynomial(enca, a, p);

        byte[] rho = new byte[32];
        params.getRandom().nextBytes(rho);

        byte[] prefix = {4};
        byte[] hash = Utils.getHashWithPrefix(prefix, publicKey.getEncoded());

        NTRULPRimePrivateKeyParameters privateKey = new NTRULPRimePrivateKeyParameters(params.getNtrulprParams(), enca, publicKey.getEncoded(),
                                                                                        rho, Arrays.copyOfRange(hash, 0, hash.length / 2));

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
