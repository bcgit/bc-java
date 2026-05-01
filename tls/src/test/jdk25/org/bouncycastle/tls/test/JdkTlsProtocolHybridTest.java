package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class JdkTlsProtocolHybridTest
    extends TlsProtocolHybridTest
{
    public JdkTlsProtocolHybridTest()
    {
        super(new JcaTlsCryptoProvider().create(new SecureRandom()));
    }
}
