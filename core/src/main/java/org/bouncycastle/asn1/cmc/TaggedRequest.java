package org.bouncycastle.asn1.cmc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.CertReqMsg;

/**
 * <pre>
 *       TaggedRequest ::= CHOICE {
 *             tcr               [0] TaggedCertificationRequest,
 *             crm               [1] CertReqMsg,
 *             orm               [2] SEQUENCE {
 *             bodyPartID            BodyPartID,
 *             requestMessageType    OBJECT IDENTIFIER,
 *             requestMessageValue   ANY DEFINED BY requestMessageType
 *      }
 *  }
 * </pre>
 */
public class TaggedRequest
    extends ASN1Object
    implements ASN1Choice
{
    public static final int TCR = 0;
    public static final int CRM = 1;
    public static final int ORM = 2;

    private final int tagNo;
    private final ASN1Encodable value;

    public TaggedRequest(TaggedCertificationRequest tcr)
    {
        this.tagNo = TCR;
        this.value = tcr;
    }

    public TaggedRequest(CertReqMsg crm)
    {
        this.tagNo = CRM;
        this.value = crm;
    }

    private TaggedRequest(ASN1Sequence orm)
    {
        this.tagNo = ORM;
        this.value = orm;
    }

    public static TaggedRequest getInstance(Object obj)
    {
        if (obj instanceof TaggedRequest)
        {
            return (TaggedRequest)obj;
        }

        if (obj != null)
        {
            if (obj instanceof ASN1Encodable)
            {
                ASN1TaggedObject asn1Prim = ASN1TaggedObject.getInstance(((ASN1Encodable)obj).toASN1Primitive());

                switch (asn1Prim.getTagNo())
                {
                case 0:
                    return new TaggedRequest(TaggedCertificationRequest.getInstance(asn1Prim, false));
                case 1:
                    return new TaggedRequest(CertReqMsg.getInstance(asn1Prim, false));
                case 2:
                    return new TaggedRequest(ASN1Sequence.getInstance(asn1Prim, false));
                default:
                    throw new IllegalArgumentException("unknown tag in getInstance(): " + asn1Prim.getTagNo());
                }
            }
            if (obj instanceof byte[])
            {
                try
                {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("unknown encoding in getInstance()");
                }
            }
            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }

        return null;
    }

    public int getTagNo()
    {
        return tagNo;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, value);
    }
}
