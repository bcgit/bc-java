package org.bouncycastle.tls.test;

import org.bouncycastle.tls.crypto.TlsNonceGenerator;

import java.util.Arrays;

class TestNonceGenerator implements TlsNonceGenerator
{
    private final byte[] baseNonce;
    private final long counterMask;
    private final int counterBytes;

    private long counterValue;
    private boolean counterExhausted;

    TestNonceGenerator(final byte[] baseNonce, final int counterBits)
    {
        this.baseNonce = Arrays.copyOf(baseNonce, baseNonce.length);
        this.counterMask = -1L >>> (64 - counterBits);
        this.counterBytes = (counterBits + 7) / 8;

        this.counterValue = 0L;
        this.counterExhausted = false;
    }

    @Override
    public byte[] generateNonce(final int size)
    {
        if (size != baseNonce.length)
        {
            throw new IllegalArgumentException("requested length is not equal to the length of the base nonce.");
        }

        if (counterExhausted)
        {
            throw new IllegalStateException("TLS nonce generator exhausted");
        }

        final byte[] nonce = Arrays.copyOf(baseNonce, baseNonce.length);
        final int offset = baseNonce.length - counterBytes;

        for (int i = 0; i < counterBytes; i++)
        {
            nonce[offset + i] ^= (byte)(counterValue >>> ((counterBytes - 1 - i) * 8));
        }

        counterExhausted |= ((++counterValue & counterMask) == 0);

        return nonce;
    }
}
