package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.openpgp.api.MissingPassphraseCallback;

import java.util.Collection;
import java.util.Collections;
import java.util.Stack;

/**
 * Test implementation of {@link MissingPassphraseCallback} which provides passphrases by popping
 * them from a provided {@link Stack}.
 */
public class StackPassphraseCallback
        implements MissingPassphraseCallback
{
    private final Stack<char[]> passphases;

    public StackPassphraseCallback(char[] passphrase)
    {
        this(Collections.singleton(passphrase));
    }

    public StackPassphraseCallback(Collection<char[]> passphrases)
    {
        this.passphases = new Stack<>();
        this.passphases.addAll(passphrases);
    }

    @Override
    public char[] getPassphrase()
    {
        if (passphases.isEmpty())
        {
            return null;
        }
        return passphases.pop();
    }
}
