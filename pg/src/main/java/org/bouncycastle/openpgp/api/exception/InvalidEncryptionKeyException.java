package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.util.Arrays;

/**
 * Exception that gets thrown if the user tries to encrypt a message for an
 * {@link org.bouncycastle.openpgp.api.OpenPGPCertificate} that does not contain any usable, valid encryption keys.
 */
public class InvalidEncryptionKeyException
        extends OpenPGPKeyException
{

    public InvalidEncryptionKeyException(OpenPGPCertificate certificate)
    {
        super(certificate, "Certificate " + certificate.getKeyIdentifier() +
                " does not contain any usable subkeys capable of encryption.");
    }

    public InvalidEncryptionKeyException(OpenPGPCertificate.OpenPGPComponentKey encryptionSubkey)
    {
        super(encryptionSubkey, componentKeyErrorMessage(encryptionSubkey));
    }

    private static String componentKeyErrorMessage(OpenPGPCertificate.OpenPGPComponentKey componentKey)
    {
        if (componentKey.getKeyIdentifier().equals(componentKey.getCertificate().getKeyIdentifier()))
        {
            return "The primary key " + componentKey.getKeyIdentifier() + " is not usable for encryption.";
        }
        else
        {
            return "The subkey " + componentKey.getKeyIdentifier() + " from the certificate " +
                    componentKey.getCertificate().getKeyIdentifier() + " is not usable for encryption.";
        }
    }
}
