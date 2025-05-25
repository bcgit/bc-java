package org.bouncycastle.openpgp.api.test;

import java.util.Collection;
import java.util.Collections;
import java.util.Stack;

import org.bouncycastle.openpgp.api.MissingMessagePassphraseCallback;

/**
 * Test implementation of {@link MissingMessagePassphraseCallback} which provides passphrases by popping
 * them from a provided {@link Stack}.
 */
public class StackMessagePassphraseCallback
        implements MissingMessagePassphraseCallback
{
    private final Stack<char[]> passphases;

    public StackMessagePassphraseCallback(char[] passphrase)
    {
        this(Collections.singleton(passphrase));
    }

    public StackMessagePassphraseCallback(Collection<char[]> passphrases)
    {
        this.passphases = new Stack<char[]>();
        this.passphases.addAll(passphrases);
    }

    public char[] getMessagePassphrase()
    {
        if (passphases.isEmpty())
        {
            return null;
        }
        return passphases.pop();
    }
}
