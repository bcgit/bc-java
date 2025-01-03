package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPException;

public class InvalidSigningKeyException
        extends PGPException
{
    public InvalidSigningKeyException(String message)
    {
        super(message);
    }
}
