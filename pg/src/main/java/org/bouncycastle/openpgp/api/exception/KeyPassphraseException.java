package org.bouncycastle.openpgp.api.exception;


import org.bouncycastle.openpgp.api.OpenPGPCertificate;

public class KeyPassphraseException
        extends OpenPGPKeyException
{
    private final Exception cause;

    public KeyPassphraseException(OpenPGPCertificate.OpenPGPComponentKey key, Exception cause)
    {
        super(key, componentKeyErrorMessage(key, cause));
        this.cause = cause;
    }

    private static String componentKeyErrorMessage(OpenPGPCertificate.OpenPGPComponentKey key, Exception cause)
    {
        if (key.getKeyIdentifier().equals(key.getCertificate().getKeyIdentifier()))
        {
            return "Cannot unlock primary key " + key.getKeyIdentifier() + ": " + cause.getMessage();
        }
        else
        {
            return "Cannot unlock subkey " + key.getKeyIdentifier() + " from key " +
                    key.getCertificate().getKeyIdentifier() + ": " + cause.getMessage();
        }
    }

    public Exception getCause()
    {
        return cause;
    }
}
