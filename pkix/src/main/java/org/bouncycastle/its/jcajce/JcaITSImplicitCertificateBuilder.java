package org.bouncycastle.its.jcajce;

import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.ITSImplicitCertificateBuilder;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.operator.DigestCalculatorProvider;

public class JcaITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{

    public JcaITSImplicitCertificateBuilder(ITSCertificate issuer, DigestCalculatorProvider digestCalculatorProvider, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, digestCalculatorProvider, tbsCertificate);
    }
}
