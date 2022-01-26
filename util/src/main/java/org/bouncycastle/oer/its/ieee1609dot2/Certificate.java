package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Certificate ::= CertificateBase (ImplicitCertificate | ExplicitCertificate)
 */
public class Certificate
    extends ASN1Object
{

    // ContentSigner & ContentVerifier

    private final CertificateBase certificateBase;

    public Certificate(CertificateBase certificateBase)
    {
        this.certificateBase = certificateBase;
    }

    public static Certificate getInstance(Object value)
    {
        if (value instanceof Certificate)
        {
            return (Certificate)value;
        }
        else
        {
            return new Certificate(CertificateBase.getInstance(value));
        }
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public CertificateBase getCertificateBase()
    {
        return certificateBase;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return certificateBase.toASN1Primitive();
    }

    public static class Builder
    {

        private CertificateBase certificateBase;

        public Builder setCertificateBase(CertificateBase certificateBase)
        {
            this.certificateBase = certificateBase;
            return this;
        }

        public Certificate createCertificate()
        {
            return new Certificate(certificateBase);
        }
    }


}
