package org.bouncycastle.pqc.crypto.ntru;

import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;

/**
 * Encapsulated secret encapsulated by NTRU.
 */
class NTRUEncapsulation
    implements SecretWithEncapsulation
{
    // implementation based on SecretWithEncapsulationImpl
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
    private final byte[] sharedKey;
    private final byte[] ciphertext;


    NTRUEncapsulation(byte[] sharedKey, byte[] ciphertext)
    {
        this.sharedKey = sharedKey;
        this.ciphertext = ciphertext;
    }

    @Override
    public byte[] getSecret()
    {
        checkDestroyed();
        return Arrays.clone(this.sharedKey);
    }

    @Override
    public byte[] getEncapsulation()
    {
        checkDestroyed();
        return Arrays.clone(this.ciphertext);
    }

    public void destroy()
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(sharedKey);
            Arrays.clear(ciphertext);
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
}
