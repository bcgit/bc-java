package org.bouncycastle.tls.test;

import org.bouncycastle.tls.crypto.impl.AEADNonceGenerator;
import org.bouncycastle.util.Arrays;

class TestAEADNonceGenerator
    implements AEADNonceGenerator
{
    private final byte[] baseNonce;
    private final long counterMask;
    private final int counterBytes;

    private long counterValue;
    private boolean counterExhausted;

    TestAEADNonceGenerator(byte[] baseNonce, int counterBits)
    {
        this.baseNonce = Arrays.copyOf(baseNonce, baseNonce.length);
        this.counterMask = -1L >>> (64 - counterBits);
        this.counterBytes = (counterBits + 7) / 8;

        this.counterValue = 0L;
        this.counterExhausted = false;
    }

    public void generateNonce(byte[] nonce)
    {
        if (nonce.length != baseNonce.length)
        {
            throw new IllegalArgumentException("requested length is not equal to the length of the base nonce.");
        }

        if (counterExhausted)
        {
            throw new IllegalStateException("TLS nonce generator exhausted");
        }

        System.arraycopy(baseNonce, 0, nonce, 0, baseNonce.length);
        int offset = baseNonce.length - counterBytes;

        for (int i = 0; i < counterBytes; i++)
        {
            nonce[offset + i] ^= (byte)(counterValue >>> ((counterBytes - 1 - i) * 8));
        }

        counterExhausted |= ((++counterValue & counterMask) == 0);
    }
}
