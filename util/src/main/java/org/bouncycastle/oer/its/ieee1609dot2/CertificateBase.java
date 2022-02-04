package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;

/**
 * <pre>
 *     CertificateBase ::= SEQUENCE {
 *         version Uint8(3),
 *         type CertificateType,
 *         issuer IssuerIdentifier,
 *         toBeSigned ToBeSignedCertificate,
 *         signature Signature OPTIONAL
 *     }
 * </pre>
 */
public class CertificateBase
    extends ASN1Object
{
    private final ASN1Integer version;
    private final CertificateType type;
    private final IssuerIdentifier issuer;
    private final ToBeSignedCertificate toBeSignedCertificate;
    private final Signature signature;


    public CertificateBase(ASN1Integer version,
                           CertificateType type,
                           IssuerIdentifier issuer,
                           ToBeSignedCertificate toBeSignedCertificate,
                           Signature signature)
    {
        this.version = version;
        this.type = type;
        this.issuer = issuer;
        this.toBeSignedCertificate = toBeSignedCertificate;
        this.signature = signature;
    }

    protected CertificateBase(ASN1Sequence seq)
    {

        if (seq.size() != 5)
        {
            throw new IllegalArgumentException("expected sequence size of 5");
        }
        version = ASN1Integer.getInstance(seq.getObjectAt(0));
        type = CertificateType.getInstance(seq.getObjectAt(1));
        issuer = IssuerIdentifier.getInstance(seq.getObjectAt(2));
        toBeSignedCertificate = ToBeSignedCertificate.getInstance(seq.getObjectAt(3));
        signature = OEROptional.getValue(Signature.class, seq.getObjectAt(4));
    }


    public static CertificateBase getInstance(Object o)
    {
        if (o instanceof CertificateBase)
        {
            return (CertificateBase)o;
        }

        if (o != null)
        {
            return new CertificateBase(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public CertificateType getType()
    {
        return type;
    }

    public IssuerIdentifier getIssuer()
    {
        return issuer;
    }

    public ToBeSignedCertificate getToBeSignedCertificate()
    {
        return toBeSignedCertificate;
    }

    public Signature getSignature()
    {
        return signature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        /*
         *   version Uint8(3),
         *         type CertificateType,
         *         issuer IssuerIdentifier,
         *         toBeSigned ToBeSignedCertificate,
         *         signature Signature OPTIONAL
         */
        return ItsUtils.toSequence(
            version,
            type,
            issuer,
            toBeSignedCertificate,
            OEROptional.getInstance(signature));
    }

    public static class Builder
    {

        private ASN1Integer version;
        private CertificateType type;
        private IssuerIdentifier issuer;
        private ToBeSignedCertificate toBeSignedCertificate;
        private Signature signature;

        public Builder setVersion(ASN1Integer version)
        {
            this.version = version;
            return this;
        }

        public Builder setType(CertificateType type)
        {
            this.type = type;
            return this;
        }

        public Builder setIssuer(IssuerIdentifier issuer)
        {
            this.issuer = issuer;
            return this;
        }

        public Builder setToBeSignedCertificate(ToBeSignedCertificate toBeSignedCertificate)
        {
            this.toBeSignedCertificate = toBeSignedCertificate;
            return this;
        }

        public Builder setSignature(Signature signature)
        {
            this.signature = signature;
            return this;
        }

        public CertificateBase createCertificateBase()
        {
            return new CertificateBase(version, type, issuer, toBeSignedCertificate, signature);
        }
    }

}
