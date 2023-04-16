package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *   RecipientInfo ::= CHOICE {
 *     pskRecipInfo         PreSharedKeyRecipientInfo,
 *     symmRecipInfo        SymmRecipientInfo,
 *     certRecipInfo        PKRecipientInfo,
 *     signedDataRecipInfo  PKRecipientInfo,
 *     rekRecipInfo         PKRecipientInfo
 *   }
 * </pre>
 */
public class RecipientInfo
    extends ASN1Object
    implements ASN1Choice
{
    public static final int pskRecipInfo = 0;
    public static final int symmRecipInfo = 1;
    public static final int certRecipInfo = 2;
    public static final int signedDataRecipInfo = 3;
    public static final int rekRecipInfo = 4;


    private final int choice;
    private final ASN1Encodable recipientInfo;


    public RecipientInfo(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.recipientInfo = value;
    }

    private RecipientInfo(ASN1TaggedObject instance)
    {
        choice = instance.getTagNo();
        switch (choice)
        {
        case pskRecipInfo:
            recipientInfo = PreSharedKeyRecipientInfo.getInstance(instance.getExplicitBaseObject());
            break;
        case symmRecipInfo:
            recipientInfo = SymmRecipientInfo.getInstance(instance.getExplicitBaseObject());
            break;
        case certRecipInfo:
        case signedDataRecipInfo:
        case rekRecipInfo:
            recipientInfo = PKRecipientInfo.getInstance(instance.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static RecipientInfo getInstance(Object object)
    {
        if (object instanceof RecipientInfo)
        {
            return (RecipientInfo)object;
        }

        if (object != null)
        {
            return new RecipientInfo(ASN1TaggedObject.getInstance(object, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getRecipientInfo()
    {
        return recipientInfo;
    }


    public static RecipientInfo pskRecipInfo(PreSharedKeyRecipientInfo info)
    {
        return new RecipientInfo(pskRecipInfo, info);
    }

    public static RecipientInfo symmRecipInfo(SymmRecipientInfo info)
    {
        return new RecipientInfo(symmRecipInfo, info);
    }

    public static RecipientInfo certRecipInfo(PKRecipientInfo info)
    {
        return new RecipientInfo(certRecipInfo, info);
    }

    public static RecipientInfo signedDataRecipInfo(PKRecipientInfo info)
    {
        return new RecipientInfo(signedDataRecipInfo, info);
    }

    public static RecipientInfo rekRecipInfo(PKRecipientInfo info)
    {
        return new RecipientInfo(rekRecipInfo, info);
    }


    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, recipientInfo);
    }
}
