package org.bouncycastle.pqc.crypto.qruov;

import org.bouncycastle.util.Arrays;

/**
 * Lightweight private key parameters for QR-UOV. Wraps the raw encoded private
 * key bytes produced by {@link QRUOVKeyPairGenerator} for the parameter set
 * carried on the superclass.
 */
public class QRUOVPrivateKeyParameters
    extends QRUOVKeyParameters
{
    private final byte[] sk;

    public QRUOVPrivateKeyParameters(QRUOVParameters params, byte[] sk)
    {
        super(true, params);

        if (sk.length != params.getPrivateKeyBytes())
        {
            throw new IllegalArgumentException("'sk' has invalid length");
        }

        this.sk = Arrays.clone(sk);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(sk);
    }
}
