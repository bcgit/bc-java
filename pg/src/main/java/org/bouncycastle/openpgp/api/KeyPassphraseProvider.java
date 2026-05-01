package org.bouncycastle.openpgp.api;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.Arrays;

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
        private final Map<OpenPGPKey.OpenPGPSecretKey, char[]> passphraseMap = new HashMap<OpenPGPKey.OpenPGPSecretKey, char[]>();
        private final List<char[]> allPassphrases = new ArrayList<char[]>();
        private KeyPassphraseProvider callback;

        public DefaultKeyPassphraseProvider()
        {

        }

        public DefaultKeyPassphraseProvider(OpenPGPKey key, char[] passphrase)
        {
            allPassphrases.add(passphrase);

            for (Iterator it = key.getSecretKeys().values().iterator(); it.hasNext(); )
            {
                OpenPGPKey.OpenPGPSecretKey subkey = (OpenPGPKey.OpenPGPSecretKey)it.next();
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
            for (Iterator it = allPassphrases.iterator(); it.hasNext();)
            {
                char[] existing = (char[])it.next();
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
