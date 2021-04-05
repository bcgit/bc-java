package org.bouncycastle.asn1.cmc;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * <pre>
 *      id-cmc-getCert OBJECT IDENTIFIER ::= {id-cmc 15}
 *
 *      GetCert ::= SEQUENCE {
 *           issuerName      GeneralName,
 *           serialNumber    INTEGER }
 * </pre>
 */
public class GetCert extends ASN1Object
{
    private final GeneralName issuerName;
    private final BigInteger serialNumber;

    private GetCert(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.issuerName = GeneralName.getInstance(seq.getObjectAt(0));
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
    }

    public GetCert(GeneralName issuerName, BigInteger serialNumber)
    {
        this.issuerName = issuerName;
        this.serialNumber = serialNumber;
    }

    public static GetCert getInstance(Object o)
    {
        if (o instanceof GetCert)
        {
            return (GetCert)o;
        }

        if (o != null)
        {
            return new GetCert(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GeneralName getIssuerName()
    {
        return issuerName;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(issuerName);
        v.add(new ASN1Integer(serialNumber));

        return new DERSequence(v);
    }
}
