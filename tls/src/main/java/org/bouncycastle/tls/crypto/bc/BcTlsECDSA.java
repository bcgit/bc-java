package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.tls.crypto.TlsSignature;

public class BcTlsECDSA implements TlsSignature
{
    protected BcTlsECDomain domain;

    public BcTlsECDSA(BcTlsECDomain domain)
    {
        this.domain = domain;
    }
}
