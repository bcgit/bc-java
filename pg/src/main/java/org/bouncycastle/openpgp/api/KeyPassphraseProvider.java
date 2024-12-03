package org.bouncycastle.openpgp.api;

import org.bouncycastle.util.Arrays;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public interface KeyPassphraseProvider
{
    /**
     * Return the passphrase for the given key.
     * This callback is only fired, if the key is locked and a passphrase is required to unlock it.
     * Returning null means, that the passphrase is not available.
     *
     * @param key the locked (sub-)key.
     * @return passphrase or null
     */
    char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key);

    class DefaultKeyPassphraseProvider
            implements KeyPassphraseProvider
    {
        private final Map<OpenPGPCertificate.OpenPGPComponentKey, char[]> passphraseMap = new HashMap<>();
        private final List<char[]> unassociatedPassphrases = new ArrayList<>();
        private KeyPassphraseProvider callback;

        public DefaultKeyPassphraseProvider()
        {

        }

        public DefaultKeyPassphraseProvider(OpenPGPKey key, char[] passphrase)
        {
            for (OpenPGPKey.OpenPGPSecretKey subkey : key.getSecretKeys().values())
            {
                passphraseMap.put(subkey, passphrase);
            }
        }

        @Override
        public char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key)
        {
            if (key.isLocked())
            {
                char[] passphrase = passphraseMap.get(key);
                if (passphrase != null)
                {
                    return passphrase;
                }

                for (char[] unassociatedPassphrase : unassociatedPassphrases)
                {
                    passphrase = unassociatedPassphrase;
                    if (key.isPassphraseCorrect(passphrase))
                    {
                        addPassphrase(key, passphrase);
                        return passphrase;
                    }
                }

                if (callback != null)
                {
                    passphrase = callback.getKeyPassword(key);
                    addPassphrase(key, passphrase);
                }
                return passphrase;
            }
            else
            {
                return null;
            }
        }

        public DefaultKeyPassphraseProvider addPassphrase(char[] passphrase)
        {
            boolean found = false;
            for (char[] existing : unassociatedPassphrases)
            {
                found |= (Arrays.areEqual(existing, passphrase));
            }

            if (!found)
            {
                unassociatedPassphrases.add(passphrase);
            }
            return this;
        }

        public DefaultKeyPassphraseProvider addPassphrase(OpenPGPKey key, char[] passphrase)
        {
            for (OpenPGPKey.OpenPGPSecretKey subkey : key.getSecretKeys().values())
            {
                addPassphrase(subkey, passphrase);
            }
            return this;
        }

        public DefaultKeyPassphraseProvider addPassphrase(OpenPGPKey.OpenPGPSecretKey key, char[] passphrase)
        {
            passphraseMap.put(key, passphrase);
            return this;
        }

        public DefaultKeyPassphraseProvider setMissingPassphraseCallback(KeyPassphraseProvider callback)
        {
            this.callback = callback;
            return this;
        }
    }
}
