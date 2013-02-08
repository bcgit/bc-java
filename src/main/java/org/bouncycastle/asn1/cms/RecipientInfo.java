package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class RecipientInfo
    extends ASN1Object
    implements ASN1Choice
{
    ASN1Encodable    info;

    public RecipientInfo(
        KeyTransRecipientInfo info)
    {
        this.info = info;
    }

    public RecipientInfo(
        KeyAgreeRecipientInfo info)
    {
        this.info = new DERTaggedObject(false, 1, info);
    }

    public RecipientInfo(
        KEKRecipientInfo info)
    {
        this.info = new DERTaggedObject(false, 2, info);
    }

    public RecipientInfo(
        PasswordRecipientInfo info)
    {
        this.info = new DERTaggedObject(false, 3, info);
    }

    public RecipientInfo(
        OtherRecipientInfo info)
    {
        this.info = new DERTaggedObject(false, 4, info);
    }

    public RecipientInfo(
        ASN1Primitive   info)
    {
        this.info = info;
    }

    public static RecipientInfo getInstance(
        Object  o)
    {
        if (o == null || o instanceof RecipientInfo)
        {
            return (RecipientInfo)o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new RecipientInfo((ASN1Sequence)o);
        }
        else if (o instanceof ASN1TaggedObject)
        {
            return new RecipientInfo((ASN1TaggedObject)o);
        }

        throw new IllegalArgumentException("unknown object in factory: "
                                                    + o.getClass().getName());
    }

    public ASN1Integer getVersion()
    {
        if (info instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject o = (ASN1TaggedObject)info;

            switch (o.getTagNo())
            {
            case 1:
                return KeyAgreeRecipientInfo.getInstance(o, false).getVersion();
            case 2:
                return getKEKInfo(o).getVersion();
            case 3:
                return PasswordRecipientInfo.getInstance(o, false).getVersion();
            case 4:
                return new ASN1Integer(0);    // no syntax version for OtherRecipientInfo
            default:
                throw new IllegalStateException("unknown tag");
            }
        }

        return KeyTransRecipientInfo.getInstance(info).getVersion();
    }

    public boolean isTagged()
    {
        return (info instanceof ASN1TaggedObject);
    }

    public ASN1Encodable getInfo()
    {
        if (info instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject o = (ASN1TaggedObject)info;

            switch (o.getTagNo())
            {
            case 1:
                return KeyAgreeRecipientInfo.getInstance(o, false);
            case 2:
                return getKEKInfo(o);
            case 3:
                return PasswordRecipientInfo.getInstance(o, false);
            case 4:
                return OtherRecipientInfo.getInstance(o, false);
            default:
                throw new IllegalStateException("unknown tag");
            }
        }

        return KeyTransRecipientInfo.getInstance(info);
    }

    private KEKRecipientInfo getKEKInfo(ASN1TaggedObject o)
    {
        if (o.isExplicit())
        {                        // compatibilty with erroneous version
            return KEKRecipientInfo.getInstance(o, true);
        }
        else
        {
            return KEKRecipientInfo.getInstance(o, false);
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * RecipientInfo ::= CHOICE {
     *     ktri KeyTransRecipientInfo,
     *     kari [1] KeyAgreeRecipientInfo,
     *     kekri [2] KEKRecipientInfo,
     *     pwri [3] PasswordRecipientInfo,
     *     ori [4] OtherRecipientInfo }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return info.toASN1Primitive();
    }
}
