package org.bouncycastle.oer.its;

/**
 * Certificate ::= CertificateBase (ImplicitCertificate | ExplicitCertificate)
 */
public class Certificate
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
            return new Builder()
                .setCertificateBase(CertificateBase.getInstance(value)).createCertificate();
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
