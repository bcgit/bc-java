package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

/**
 * Implementation of null PRNG returning zeroes only. For testing purposes
 * only(!).
 */
public final class NullPRNG
    extends SecureRandom
{

    private static final long serialVersionUID = 1L;

    public NullPRNG()
    {
        super();
    }
    
    public void nextBytes(byte[] bytes)
    {
        for (int i = 0; i < bytes.length; i++)
        {
            bytes[i] = 0x00;
        }
    }
}
