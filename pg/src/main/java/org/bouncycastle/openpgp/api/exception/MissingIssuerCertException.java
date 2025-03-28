package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.api.OpenPGPSignature;

/**
 * The OpenPGP certificate (public key) required to verify a signature is not available.
 */
public class MissingIssuerCertException
        extends OpenPGPSignatureException
{
    public MissingIssuerCertException(OpenPGPSignature signature, String message)
    {
        super(signature, message);
    }
}
