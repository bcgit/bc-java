package org.bouncycastle.tls.test;

import org.bouncycastle.tls.crypto.impl.AEADNonceGenerator;
import org.bouncycastle.tls.crypto.impl.AEADNonceGeneratorFactory;

public class TestAEADGeneratorFactory
    implements AEADNonceGeneratorFactory
{
    public static final AEADNonceGeneratorFactory INSTANCE = new TestAEADGeneratorFactory();

    private TestAEADGeneratorFactory()
    {
        // no op
    }

    public AEADNonceGenerator create(byte[] baseNonce, int counterSizeInBits)
    {
        return new TestAEADNonceGenerator(baseNonce, counterSizeInBits);
    }
}
