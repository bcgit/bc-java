package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPSignatureException;

/**
 * An OpenPGP Signature is malformed (missing required subpackets, etc.).
 */
public class MalformedPGPSignatureException
        extends PGPSignatureException
{

    public MalformedPGPSignatureException(String message)
    {
        super(message);
    }
}
