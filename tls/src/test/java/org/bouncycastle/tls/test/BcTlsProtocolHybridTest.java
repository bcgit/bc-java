package org.bouncycastle.tls.test;

import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class BcTlsProtocolHybridTest
    extends TlsProtocolHybridTest
{
    public BcTlsProtocolHybridTest()
    {
        super(new BcTlsCrypto());
    }
}
