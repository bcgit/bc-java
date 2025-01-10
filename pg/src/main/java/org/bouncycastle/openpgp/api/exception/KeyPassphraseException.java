package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPException;

public class KeyPassphraseException
        extends PGPException
{
    public KeyPassphraseException(Exception cause)
    {
        super("Cannot unlock secret key", cause);
    }
}
