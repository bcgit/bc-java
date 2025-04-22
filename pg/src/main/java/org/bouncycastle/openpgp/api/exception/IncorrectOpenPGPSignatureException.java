package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.api.OpenPGPSignature;

/**
 * An OpenPGP signature is not correct.
 */
public class IncorrectOpenPGPSignatureException
        extends OpenPGPSignatureException
{
    public IncorrectOpenPGPSignatureException(OpenPGPSignature signature, String message)
    {
        super(signature, message);
    }
}
