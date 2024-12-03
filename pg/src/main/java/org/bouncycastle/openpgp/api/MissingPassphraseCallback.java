package org.bouncycastle.openpgp.api;

public interface MissingPassphraseCallback
{
    /**
     * Return a passphrase for message decryption.
     * Returning null means, that no passphrase is available and decryption is aborted.
     *
     * @return passphrase
     */
    char[] getPassphrase();

}
