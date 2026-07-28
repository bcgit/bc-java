package org.bouncycastle.crypto.ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

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

        ECCurve curve = key.getParameters().getCurve();
        // the ciphertext point is externally supplied and d is the long-term private key:
        // constant-time, not the curve's default wNAF multiplier
        ECPoint tmp = ECAlgorithms.multiplySecret(
            ECAlgorithms.cleanPoint(curve, pair.getX()), key.getD(), key.getParameters().getN());

        return ECAlgorithms.cleanPoint(curve, pair.getY()).subtract(tmp).normalize();
    }
}
