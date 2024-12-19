package org.bouncycastle.tls.test;

import org.bouncycastle.jsse.provider.TlsNonceGeneratorFactory;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;

class TestTlsNonceGeneratorFactory implements TlsNonceGeneratorFactory {
    public static final TlsNonceGeneratorFactory INSTANCE = new TestTlsNonceGeneratorFactory();

    private TestTlsNonceGeneratorFactory()
    {
        // no op
    }

    @Override
    public TlsNonceGenerator create(final byte[] baseNonce, final int counterSizeInBits)
    {
        return new TestNonceGenerator(baseNonce, counterSizeInBits);
    }
}
