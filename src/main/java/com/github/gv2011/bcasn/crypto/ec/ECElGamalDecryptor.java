package com.github.gv2011.bcasn.crypto.ec;

import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.crypto.params.ECPrivateKeyParameters;
import com.github.gv2011.bcasn.math.ec.ECPoint;

/**
 * this does your basic decryption ElGamal style using EC
 */
public class ECElGamalDecryptor
    implements ECDecryptor
{
    private ECPrivateKeyParameters key;

    /**
     * initialise the decryptor.
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
     * Decrypt an EC pair producing the original EC point.
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

        ECPoint tmp = pair.getX().multiply(key.getD());

        return pair.getY().subtract(tmp).normalize();
    }
}
