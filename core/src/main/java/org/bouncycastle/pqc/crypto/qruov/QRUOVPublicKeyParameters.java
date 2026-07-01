package org.bouncycastle.pqc.crypto.qruov;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight public key parameters for QR-UOV. Wraps the raw encoded public
 * key bytes produced by {@link QRUOVKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class QRUOVPublicKeyParameters
    extends QRUOVKeyParameters
{
    private final byte[] pk;

    public QRUOVPublicKeyParameters(QRUOVParameters params, byte[] pk)
    {
        super(false, params);

        if (pk.length != params.getPublicKeyBytes())
        {
            throw new IllegalArgumentException("'pk' has invalid length");
        }

        this.pk = Arrays.clone(pk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(pk);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }
}
