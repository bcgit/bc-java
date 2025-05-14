package org.bouncycastle.tls.test;

import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class BcTlsProtocolKemTest
    extends TlsProtocolKemTest
{
    public BcTlsProtocolKemTest()
    {
        super(new BcTlsCrypto());
    }
}
