package org.bouncycastle.tls.crypto.jcajce;

import org.bouncycastle.tls.crypto.TlsSignature;

public class JcaTlsECDSA
    implements TlsSignature
{
    protected JcaTlsECDomain domain;

    public JcaTlsECDSA(JcaTlsECDomain domain)
    {
        this.domain = domain;
    }
}
