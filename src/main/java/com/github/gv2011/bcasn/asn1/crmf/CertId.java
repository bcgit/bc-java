package com.github.gv2011.bcasn.asn1.crmf;

import java.math.BigInteger;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.x509.GeneralName;

public class CertId
    extends ASN1Object
{
    private GeneralName issuer;
    private ASN1Integer serialNumber;

    private CertId(ASN1Sequence seq)
    {
        issuer = GeneralName.getInstance(seq.getObjectAt(0));
        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public static CertId getInstance(Object o)
    {
        if (o instanceof CertId)
        {
            return (CertId)o;
        }

        if (o != null)
        {
            return new CertId(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static CertId getInstance(ASN1TaggedObject obj, boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public CertId(GeneralName issuer, BigInteger serialNumber)
    {
        this(issuer, new ASN1Integer(serialNumber));
    }

    public CertId(GeneralName issuer, ASN1Integer serialNumber)
    {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
    }

    public GeneralName getIssuer()
    {
        return issuer;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * <pre>
     * CertId ::= SEQUENCE {
     *                 issuer           GeneralName,
     *                 serialNumber     INTEGER }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(issuer);
        v.add(serialNumber);
        
        return new DERSequence(v);
    }
}
