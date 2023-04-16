package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
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

    private final int choice;
    private final ASN1Encodable certificateId;

    public CertificateId(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.certificateId = value;
    }

    private CertificateId(ASN1TaggedObject asn1TaggedObject)
    {
        choice = asn1TaggedObject.getTagNo();
        switch (choice)
        {
        case linkageData:
            certificateId = LinkageData.getInstance(asn1TaggedObject.getExplicitBaseObject());
            break;
        case name:
            certificateId = Hostname.getInstance(asn1TaggedObject.getExplicitBaseObject());
            break;
        case binaryId:
            certificateId = DEROctetString.getInstance(asn1TaggedObject.getExplicitBaseObject());
            break;
        case none:
            certificateId = ASN1Null.getInstance(asn1TaggedObject.getExplicitBaseObject());
            break;

        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static CertificateId linkageData(LinkageData linkageData)
    {
        return new CertificateId(CertificateId.linkageData, linkageData);
    }

    public static CertificateId name(Hostname hostname)
    {
        return new CertificateId(CertificateId.name, hostname);
    }

    public static CertificateId binaryId(ASN1OctetString stream)
    {
        return new CertificateId(CertificateId.binaryId, stream);
    }

    public static CertificateId binaryId(byte[] stream)
    {
        return new CertificateId(CertificateId.binaryId, new DEROctetString(stream));
    }

    public static CertificateId none()
    {
        return new CertificateId(CertificateId.none, DERNull.INSTANCE);
    }

    public static CertificateId getInstance(Object o)
    {
        if (o instanceof CertificateId)
        {
            return (CertificateId)o;
        }

        if (o != null)
        {
            return new CertificateId(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, certificateId).toASN1Primitive();
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getCertificateId()
    {
        return certificateId;
    }

}
