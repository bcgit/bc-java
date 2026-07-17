package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;

public class SecretWithEncapsulationImpl
    implements SecretWithEncapsulation
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] sessionKey;
    private final byte[] cipher_text;

    public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
    {
        this.sessionKey = sessionKey;
        this.cipher_text = cipher_text;
    }

    public byte[] getSecret()
    {
        checkDestroyed();

        return Arrays.clone(sessionKey);
    }

    public byte[] getEncapsulation()
    {
        checkDestroyed();

        return Arrays.clone(cipher_text);
    }

    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(sessionKey);
            Arrays.clear(cipher_text);
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    void checkDestroyed()
    {
        if (isDestroyed())
        {
            throw new IllegalStateException("data has been destroyed");
        }
    }

    private static class AtomicBoolean
    {
        private volatile boolean value;

        AtomicBoolean(boolean value)
        {
            this.value = value;
        }

        public synchronized void set(boolean value)
        {
            this.value = value;
        }

        public synchronized boolean getAndSet(boolean value)
        {
            boolean tmp = this.value;

            this.value = value;

            return tmp;
        }

        public synchronized boolean get()
        {
            return this.value;
        }
    }
}
