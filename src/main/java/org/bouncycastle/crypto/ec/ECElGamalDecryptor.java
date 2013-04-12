package org.bouncycastle.crypto.ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * this does your basic Elgamal algorithm using EC
 */
public class ECElGamalDecryptor
{
    private ECPrivateKeyParameters key;

    /**
     * initialise the EC Elgamal engine.
     *
     * @param param the necessary EC key parameters.
     */
    public void init(
        CipherParameters param)
    {
        if (!(param instanceof ECPrivateKeyParameters))
        {
            throw new IllegalArgumentException("ECPrivateKeyParameters are required for decryption.");
        }

        this.key = (ECPrivateKeyParameters)param;
    }

    /**
     * Process a single EC point using the basic Elgamal algorithm.
     *
     * @param pair the EC point pair to process.
     * @return the result of the Elgamal process.
     */
    public ECPoint decrypt(ECPair pair)
    {
        if (key == null)
        {
            throw new IllegalStateException("ECElGamalDecryptor not initialised");
        }

        ECPoint tmp = pair.getA().multiply(key.getD());

        return pair.getB().add(tmp.negate());
    }
}
