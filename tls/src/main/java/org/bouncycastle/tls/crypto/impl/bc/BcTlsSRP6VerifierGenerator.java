package org.bouncycastle.tls.crypto.impl.bc;

import java.math.BigInteger;

import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.tls.crypto.TlsSRP6VerifierGenerator;

final class BcTlsSRP6VerifierGenerator
    implements TlsSRP6VerifierGenerator
{
    private final SRP6VerifierGenerator srp6VerifierGenerator;

    BcTlsSRP6VerifierGenerator(SRP6VerifierGenerator srp6VerifierGenerator)
    {
        this.srp6VerifierGenerator = srp6VerifierGenerator;
    }

    public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
    {
        return srp6VerifierGenerator.generateVerifier(salt, identity, password);
    }
}
