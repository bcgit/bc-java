package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPSignatureException;

/**
 * The OpenPGP certificate (public key) required to verify a signature is not available.
 */
public class MissingIssuerCertException
        extends PGPSignatureException
{
    public MissingIssuerCertException(String message)
    {
        super(message);
    }
}
