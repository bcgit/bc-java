package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * Certificate ::= CertificateBase (ImplicitCertificate | ExplicitCertificate)
 */
public class Certificate
    extends CertificateBase
{
    public Certificate(UINT8 version, CertificateType type, IssuerIdentifier issuer, ToBeSignedCertificate toBeSignedCertificate, Signature signature)
    {
        super(version, type, issuer, toBeSignedCertificate, signature);
    }

    public Certificate(CertificateBase base)
    {
        this(base.getVersion(), base.getType(), base.getIssuer(), base.getToBeSigned(), base.getSignature());
    }

    protected Certificate(ASN1Sequence seq)
    {
        super(seq);
    }


    public static Certificate getInstance(Object value)
    {
        if (value instanceof Certificate)
        {
            return (Certificate)value;
        }

        if (value != null)
        {
            return new Certificate(ASN1Sequence.getInstance(value));
        }
        return null;
    }

}
