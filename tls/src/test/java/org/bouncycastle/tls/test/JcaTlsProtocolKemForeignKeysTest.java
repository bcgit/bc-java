package org.bouncycastle.tls.test;

import java.security.SecureRandom;

/**
 * TlsProtocolKemTest with ML-KEM keys supplied as non-BC key objects while BC performs the KEM (github #2466).
 */
public class JcaTlsProtocolKemForeignKeysTest
    extends TlsProtocolKemTest
{
    public JcaTlsProtocolKemForeignKeysTest()
    {
        super(new ForeignMLKEMKeysCryptoProvider().create(new SecureRandom()));
    }
}
