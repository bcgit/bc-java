package org.bouncycastle.tls.crypto.test;

import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class BcTlsCryptoTest
    extends TlsCryptoTest
{
    public BcTlsCryptoTest()
    {
        super(new BcTlsCrypto());
    }
}
