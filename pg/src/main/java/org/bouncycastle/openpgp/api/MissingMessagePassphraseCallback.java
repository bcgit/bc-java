package org.bouncycastle.openpgp.api;

public interface MissingMessagePassphraseCallback
{
    /**
     * Return a passphrase for message decryption.
     * Returning null means, that no passphrase is available and decryption is aborted.
     *
     * @return passphrase
     */
    char[] getMessagePassphrase();

}
