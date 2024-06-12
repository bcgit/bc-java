package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * RecipientInfo ::= CHOICE {
 *     ktri      KeyTransRecipientInfo,
 *     kari  [1] KeyAgreeRecipientInfo,
 *     kekri [2] KEKRecipientInfo,
 *     pwri  [3] PasswordRecipientInfo,
 *     ori   [4] OtherRecipientInfo }
 * </pre>
 */
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

    /**
     * Return a RecipientInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link RecipientInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with RecipientInfo structure inside
     * <li> {@link org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject} input formats with RecipientInfo structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
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

    /** @deprecated Will be removed */
    public ASN1Integer getVersion()
    {
        if (!(info instanceof ASN1TaggedObject))
        {
            return KeyTransRecipientInfo.getInstance(info).getVersion();
        }

        ASN1TaggedObject tagged = (ASN1TaggedObject)info;
        if (tagged.hasContextTag())
        {
            switch (tagged.getTagNo())
            {
            case 1:
                return KeyAgreeRecipientInfo.getInstance(tagged, false).getVersion();
            case 2:
                return getKEKInfo(tagged).getVersion();
            case 3:
                return PasswordRecipientInfo.getInstance(tagged, false).getVersion();
            case 4:
                return new ASN1Integer(0);    // no syntax version for OtherRecipientInfo
            }
        }
        throw new IllegalStateException("unknown tag");
    }

    public boolean isTagged()
    {
        return info instanceof ASN1TaggedObject;
    }

    public ASN1Encodable getInfo()
    {
        if (!(info instanceof ASN1TaggedObject))
        {
            return KeyTransRecipientInfo.getInstance(info);
        }

        ASN1TaggedObject tagged = (ASN1TaggedObject)info;
        if (tagged.hasContextTag())
        {
            switch (tagged.getTagNo())
            {
            case 1:
                return KeyAgreeRecipientInfo.getInstance(tagged, false);
            case 2:
                return getKEKInfo(tagged);
            case 3:
                return PasswordRecipientInfo.getInstance(tagged, false);
            case 4:
                return OtherRecipientInfo.getInstance(tagged, false);
            }
        }
        throw new IllegalStateException("unknown tag");
    }

    private KEKRecipientInfo getKEKInfo(ASN1TaggedObject o)
    {
        // For compatibility with erroneous version, we don't always pass 'false' here
        boolean declaredExplicit = o.isExplicit();

        return KEKRecipientInfo.getInstance(o, declaredExplicit);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return info.toASN1Primitive();
    }

    boolean isKeyTransV0()
    {
        if (info instanceof ASN1TaggedObject)
        {
            return false;
        }

        KeyTransRecipientInfo ktri = KeyTransRecipientInfo.getInstance(info);

        return ktri.getVersion().hasValue(0);
    }

    boolean isPasswordOrOther()
    {
        if (info instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject)info;
            if (tagged.hasContextTag())
            {
                switch (tagged.getTagNo())
                {
                case 3:
                case 4:
                    return true;
                }
            }
        }
        return false;
    }
}
