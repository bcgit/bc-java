package org.bouncycastle.crypto.io;

import java.io.IOException;

/**
 * {@link IOException} wrapper around an exception indicating an invalid ciphertext, such as in
 * authentication failure during finalisation of an AEAD cipher. For use in streams that need to
 * expose invalid ciphertext errors.
 */
public class InvalidCipherTextIOException
    extends IOException
{
    private static final long serialVersionUID = 1L;

    public InvalidCipherTextIOException(final String message, final Throwable cause)
    {
        super(message, cause);
    }
}