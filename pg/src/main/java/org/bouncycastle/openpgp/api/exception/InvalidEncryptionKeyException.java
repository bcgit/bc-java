package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPException;

/**
 * Exception that gets thrown if the user tries to encrypt a message for an
 * {@link org.bouncycastle.openpgp.api.OpenPGPCertificate} that does not contain any usable, valid encryption keys.
 */
public class InvalidEncryptionKeyException
        extends PGPException
{
    public InvalidEncryptionKeyException(String message)
    {
        super(message);
    }
}
