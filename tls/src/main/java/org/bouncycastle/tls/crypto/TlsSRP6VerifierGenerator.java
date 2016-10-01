package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

public interface TlsSRP6VerifierGenerator
{
    BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password);
}
