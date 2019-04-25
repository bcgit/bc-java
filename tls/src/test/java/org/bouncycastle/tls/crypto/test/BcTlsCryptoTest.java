package org.bouncycastle.tls.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class BcTlsCryptoTest
    extends TlsCryptoTest
{
    public BcTlsCryptoTest()
    {
        super(new BcTlsCrypto(new SecureRandom()));
    }
}
