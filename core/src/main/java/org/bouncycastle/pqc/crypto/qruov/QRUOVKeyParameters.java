package org.bouncycastle.pqc.crypto.qruov;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Common base for QR-UOV public and private key parameter classes; carries the
 * {@link QRUOVParameters} parameter set the key belongs to.
 */
public class QRUOVKeyParameters
    extends AsymmetricKeyParameter
{
    private final QRUOVParameters params;

    public QRUOVKeyParameters(boolean isPrivate, QRUOVParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public QRUOVParameters getParameters()
    {
        return params;
    }
}
