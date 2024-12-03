package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPSignatureException;

/**
 * An OpenPGP signature is not correct.
 */
public class IncorrectPGPSignatureException
        extends PGPSignatureException
{
    public IncorrectPGPSignatureException(String message)
    {
        super(message);
    }
}
