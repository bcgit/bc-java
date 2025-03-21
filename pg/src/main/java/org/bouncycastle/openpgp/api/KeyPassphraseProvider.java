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
        private final Map<OpenPGPKey.OpenPGPSecretKey, char[]> passphraseMap = new HashMap<>();
        private final List<char[]> allPassphrases = new ArrayList<>();
        private KeyPassphraseProvider callback;

        public DefaultKeyPassphraseProvider()
        {

        }

        public DefaultKeyPassphraseProvider(OpenPGPKey key, char[] passphrase)
        {
            allPassphrases.add(passphrase);
            for (OpenPGPKey.OpenPGPSecretKey subkey : key.getSecretKeys().values())
            {
                passphraseMap.put(subkey, passphrase);
            }
        }

        @Override
        public char[] getKeyPassword(OpenPGPKey.OpenPGPSecretKey key)
        {
            if (!key.isLocked())
            {
                passphraseMap.put(key, null);
                return null;
            }

            char[] passphrase = passphraseMap.get(key);
            if (passphrase != null)
            {
                return passphrase;
            }

            for (char[] knownPassphrase : allPassphrases)
            {
                if (key.isPassphraseCorrect(knownPassphrase))
                {
                    addPassphrase(key, knownPassphrase);
                    return knownPassphrase;
                }
            }

            if (callback != null)
            {
                passphrase = callback.getKeyPassword(key);
                addPassphrase(key, passphrase);
            }
            return passphrase;
        }

        public DefaultKeyPassphraseProvider addPassphrase(char[] passphrase)
        {
            boolean found = false;
            for (char[] existing : allPassphrases)
            {
                found |= (Arrays.areEqual(existing, passphrase));
            }

            if (!found)
            {
                allPassphrases.add(passphrase);
            }
            return this;
        }

        public DefaultKeyPassphraseProvider addPassphrase(OpenPGPKey key, char[] passphrase)
        {
            for (OpenPGPKey.OpenPGPSecretKey subkey : key.getSecretKeys().values())
            {
                if (!subkey.isLocked())
                {
                    passphraseMap.put(subkey, null);
                    continue;
                }

                char[] existentPassphrase = passphraseMap.get(subkey);
                if (existentPassphrase == null || !subkey.isPassphraseCorrect(existentPassphrase))
                {
                    passphraseMap.put(subkey, passphrase);
                }
            }
            return this;
        }

        public DefaultKeyPassphraseProvider addPassphrase(OpenPGPKey.OpenPGPSecretKey key, char[] passphrase)
        {
            if (!key.isLocked())
            {
                passphraseMap.put(key, null);
                return this;
            }

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
