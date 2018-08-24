package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECDomain;

public class BcX25519Domain implements TlsECDomain
{
    protected final BcTlsCrypto crypto;

    public BcX25519Domain(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public TlsAgreement createECDH()
    {
        return new BcX25519(crypto);
    }
}
