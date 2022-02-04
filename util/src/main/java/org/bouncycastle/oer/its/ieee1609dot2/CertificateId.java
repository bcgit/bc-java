package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Hostname;

/**
 * CertificateId ::= CHOICE {
 * linkageData  LinkageData,
 * name         Hostname,
 * binaryId     OCTET STRING(SIZE(1..64)),
 * none         NULL,
 * ...
 * }
 */
public class CertificateId
    extends ASN1Object
    implements ASN1Choice
{

    public static final int linkageData = 0;
    public static final int name = 1;
    public static final int binaryId = 2;
    public static final int none = 3;
    public static final int extension = 4;

    private final int choice;
    private final ASN1Encodable value;

    public CertificateId(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    private CertificateId(ASN1TaggedObject asn1TaggedObject)
    {
        choice = asn1TaggedObject.getTagNo();
        switch (choice)
        {
        case linkageData:
            value = LinkageData.getInstance(asn1TaggedObject.getObject());
            break;
        case name:
            value = Hostname.getInstance(asn1TaggedObject.getObject());
            break;
        case binaryId:
            value = DEROctetString.getInstance(asn1TaggedObject.getObject());
            break;
        case none:
            value = ASN1Null.getInstance(asn1TaggedObject.getObject());
            break;
        case extension:
            value = DEROctetString.getInstance(asn1TaggedObject.getObject());
            break;


        default:
            throw new IllegalArgumentException("invalid choice value "+choice);
        }
    }

    public static CertificateId getInstance(Object o)
    {
        if (o instanceof CertificateId)
        {
            return (CertificateId)o;
        }

        if (o != null)
        {
            return new CertificateId(ASN1TaggedObject.getInstance(o));
        }

        return null;

    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value).toASN1Primitive();
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public static class Builder
    {
        private int choice;
        private ASN1Encodable value;


        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setValue(ASN1Encodable value)
        {
            this.value = value;
            return this;
        }

        public Builder linkageData(LinkageData data)
        {
            this.choice = linkageData;
            this.value = data;
            return this;
        }

        public Builder name(Hostname data)
        {
            this.choice = name;
            this.value = data;
            return this;
        }

        public Builder binaryId(DEROctetString data)
        {
            this.choice = name;
            this.value = data;
            return this;
        }

        public Builder none()
        {
            this.choice = name;
            this.value = DERNull.INSTANCE;
            return this;
        }

        public Builder extension(byte[] data)
        {
            this.choice = extension;
            this.value = new DEROctetString(data);
            return this;
        }

        public CertificateId createCertificateId()
        {
            return new CertificateId(choice, value);
        }

    }


}
