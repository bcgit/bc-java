package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class JdkTlsProtocolKemTest
    extends TlsProtocolKemTest
{
    public JdkTlsProtocolKemTest()
    {
        super(new JcaTlsCryptoProvider().create(new SecureRandom()));
    }
}
