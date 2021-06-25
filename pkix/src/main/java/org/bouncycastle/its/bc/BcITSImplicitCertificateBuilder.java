package org.bouncycastle.its.bc;

import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSImplicitCertificateBuilder;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{
    public BcITSImplicitCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
    }
}
