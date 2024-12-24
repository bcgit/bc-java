package org.bouncycastle.tls.test;

import org.bouncycastle.tls.crypto.impl.AEADNonceGenerator;
import org.bouncycastle.tls.crypto.impl.AEADNonceGeneratorFactory;

class TestAEADGeneratorFactory
    implements AEADNonceGeneratorFactory
{
    public static final AEADNonceGeneratorFactory INSTANCE = new TestAEADGeneratorFactory();

    private TestAEADGeneratorFactory()
    {
        // no op
    }

    @Override
    public AEADNonceGenerator create(final byte[] baseNonce, final int counterSizeInBits)
    {
        return new TestAEADNonceGenerator(baseNonce, counterSizeInBits);
    }
}
