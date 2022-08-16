package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.Arrays;

public class SNTRUPrimeKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SNTRUPrimeKeyGenerationParameters params;

    public SNTRUPrimeKeyGenerationParameters getParams()
    {
        return params;
    }

    /**
     * Initialize the Key Pair Generator.
     *
     * @param param the parameters the key pair is to be initialised with.
     */
    public void init(KeyGenerationParameters param)
    {
        this.params = (SNTRUPrimeKeyGenerationParameters) param;
    }

    /**
     * return an AsymmetricCipherKeyPair containing the generated keys.
     *
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int p = params.getSntrupParams().getP();
        int q = params.getSntrupParams().getQ();
        int w = params.getSntrupParams().getW();

        /*
         * Generate Random Small Polynomial g from R/3 until it is invertible in R/3
         * Generate Inverse of Random Small Polynomial (1/g) in R/3
         */
        byte[] g = new byte[p];
        byte[] ginv = new byte[p];
        do Utils.getRandomSmallPolynomial(params.getRandom(), g);
            while (!Utils.isInvertiblePolynomialInR3(g, ginv, p));

        /*
         * Generate Random Short Polynomial from R/3 with weight w
         * Generate Inverse of Random Short Polynomial (1/3f) in R/q
         */
        byte[] f = new byte[p];
        Utils.getRandomShortPolynomial(params.getRandom(), f, p, w);

        short[] finv3 = new short[p];
        Utils.getOneThirdInverseInRQ(finv3, f, p, q);

        /*
         * Compute h = g/3f in R/q
         */
        short[] h = new short[p];
        Utils.multiplicationInRQ(h, finv3, g, p, q);

        /*
         * Public Key = Encode(h)
         */
        byte[] pk = new byte[params.getSntrupParams().getPublicKeyBytes()];
        Utils.getEncodedPolynomial(pk, h, p, q);

        SNTRUPrimePublicKeyParameters publicKey = new SNTRUPrimePublicKeyParameters(params.getSntrupParams(), pk);

        /*
         * Private Key = Encode(f) | Encode(1/g) | pk | Random rho | SHA-512(4|pk)
         */
        byte[] encF = new byte[(p + 3) / 4];
        Utils.getEncodedSmallPolynomial(encF, f, p);

        byte[] encGinv = new byte[(p + 3) / 4];
        Utils.getEncodedSmallPolynomial(encGinv, ginv, p);

        byte[] rho = new byte[(p + 3) / 4];
        params.getRandom().nextBytes(rho);

        byte[] prefix = {4};
        byte[] hash = Utils.getHashWithPrefix(prefix, pk);

        SNTRUPrimePrivateKeyParameters privateKey = new SNTRUPrimePrivateKeyParameters(params.getSntrupParams(), encF, encGinv,
                                                                                        pk, rho, Arrays.copyOfRange(hash, 0, hash.length / 2));

        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
