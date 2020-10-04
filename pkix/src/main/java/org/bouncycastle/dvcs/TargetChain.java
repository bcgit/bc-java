package org.bouncycastle.dvcs;

import org.bouncycastle.dvcs.asn1.TargetEtcChain;

public class TargetChain
{
    private final TargetEtcChain certs;

    public TargetChain(TargetEtcChain certs)
    {
        this.certs = certs;
    }

    public TargetEtcChain toASN1Structure()
    {
        return certs;
    }
}
