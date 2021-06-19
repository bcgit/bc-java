package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class CertificateId
    extends ASN1Object
    implements ASN1Choice
{

    public static final int linkageData = 0;
    public static final int name = 1;
    public static final int binaryId = 2;
    public static final int none = 3;

    private final int choice;
    private final ASN1Primitive value;

    public CertificateId(int choice, ASN1Primitive value)
    {
        this.choice = choice;
        this.value = value;
    }

    public static CertificateId getInstance(Object o)
    {
        if (o instanceof CertificateId)
        {
            return (CertificateId)o;
        }
        else
        {
            ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(o);
            int item = asn1TaggedObject.getTagNo();
            switch (item)
            {
            case linkageData:
            case name:
            case binaryId:
            case none:
                return new CertificateId(item, asn1TaggedObject.getObject());

            default:
                throw new IllegalArgumentException("unknown choice in CertificateId");
            }
        }

    }


    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value).toASN1Primitive();
    }

    public int getChoice()
    {
        return choice;
    }

    public static class Builder
    {

    }


}
