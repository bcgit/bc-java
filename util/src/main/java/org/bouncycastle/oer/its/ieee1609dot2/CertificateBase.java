package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097Certificate;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

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
    private final UINT8 version;
    private final CertificateType type;
    private final IssuerIdentifier issuer;
    private final ToBeSignedCertificate toBeSigned;
    private final Signature signature;


    public CertificateBase(UINT8 version,
                           CertificateType type,
                           IssuerIdentifier issuer,
                           ToBeSignedCertificate toBeSignedCertificate,
                           Signature signature)
    {
        this.version = version;
        this.type = type;
        this.issuer = issuer;
        this.toBeSigned = toBeSignedCertificate;
        this.signature = signature;
    }

    protected CertificateBase(ASN1Sequence seq)
    {

        if (seq.size() != 5)
        {
            throw new IllegalArgumentException("expected sequence size of 5");
        }
        version = UINT8.getInstance(seq.getObjectAt(0));
        type = CertificateType.getInstance(seq.getObjectAt(1));
        issuer = IssuerIdentifier.getInstance(seq.getObjectAt(2));
        toBeSigned = ToBeSignedCertificate.getInstance(seq.getObjectAt(3));
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

    public UINT8 getVersion()
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

    public ToBeSignedCertificate getToBeSigned()
    {
        return toBeSigned;
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
            toBeSigned,
            OEROptional.getInstance(signature));
    }

    public static class Builder
    {

        private UINT8 version;
        private CertificateType type;
        private IssuerIdentifier issuer;
        private ToBeSignedCertificate toBeSigned;
        private Signature signature;


        public Builder setVersion(UINT8 version)
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

        public Builder setToBeSigned(ToBeSignedCertificate toBeSigned)
        {
            this.toBeSigned = toBeSigned;
            return this;
        }

        public Builder setSignature(Signature signature)
        {
            this.signature = signature;
            return this;
        }

        public Certificate createCertificate()
        {
            return new Certificate(version, type, issuer, toBeSigned, signature);
        }

        public ExplicitCertificate createExplicitCertificate()
        {
            return new ExplicitCertificate(version, issuer, toBeSigned, signature);
        }

        public ImplicitCertificate createImplicitCertificate()
        {
            return new ImplicitCertificate(version, issuer, toBeSigned, signature);
        }

        public CertificateBase createCertificateBase()
        {
            return new CertificateBase(version, type, issuer, toBeSigned, signature);
        }

        public CertificateBase createEtsiTs103097Certificate()
        {
            return new EtsiTs103097Certificate(version, issuer, toBeSigned, signature);
        }
    }

}
