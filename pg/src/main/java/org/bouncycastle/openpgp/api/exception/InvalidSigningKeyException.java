package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;

public class InvalidSigningKeyException
        extends OpenPGPKeyException
{

    public InvalidSigningKeyException(OpenPGPKey key)
    {
        super(key, "The key " + key.getKeyIdentifier() +
                " does not contain any usable component keys capable of signing.");
    }

    public InvalidSigningKeyException(OpenPGPCertificate.OpenPGPComponentKey componentKey)
    {
        super(componentKey, componentKeyErrorMessage(componentKey));
    }

    private static String componentKeyErrorMessage(OpenPGPCertificate.OpenPGPComponentKey componentKey)
    {
        if (componentKey.getKeyIdentifier().equals(componentKey.getCertificate().getKeyIdentifier()))
        {
            return "The primary key " + componentKey.getKeyIdentifier() + " is not usable for signing.";
        }
        else
        {
            return "The subkey " + componentKey.getKeyIdentifier() + " from the certificate " +
                    componentKey.getCertificate().getKeyIdentifier() + " is not usable for signing.";
        }
    }
}
