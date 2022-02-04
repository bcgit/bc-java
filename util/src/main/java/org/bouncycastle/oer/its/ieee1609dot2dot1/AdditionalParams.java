package org.bouncycastle.oer.its.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;

/**
 * AdditionalParams ::= CHOICE {
 * original        ButterflyParamsOriginal,
 * unified         ButterflyExpansion,
 * compactUnified  ButterflyExpansion,
 * encryptionKey   PublicEncryptionKey,
 * ...
 * }
 */
public class AdditionalParams
    extends ASN1Object
    implements ASN1Choice
{

    public static final int original = 0;
    public static final int unified = 1;
    public static final int compactUnified = 2;
    public static final int encryptionKey = 3;
    public static final int extension = 4;

    protected final int choice;
    protected final ASN1Encodable additionalParams;


    private AdditionalParams(int choice, ASN1Encodable additionalParams)
    {
        switch (choice)
        {
        case original:
            this.additionalParams = ButterflyParamsOriginal.getInstance(additionalParams);
            break;
        case unified:
        case compactUnified:
            this.additionalParams = ButterflyExpansion.getInstance(additionalParams);
            break;
        case encryptionKey:
            this.additionalParams = PublicEncryptionKey.getInstance(additionalParams);
            break;
        case extension:
            this.additionalParams = DEROctetString.getInstance(additionalParams);
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
        this.choice = choice;
    }

    private AdditionalParams(ASN1TaggedObject ato) {
        this(ato.getTagNo(),ato.getObject());
    }

    public static AdditionalParams getInstance(Object o)
    {
        if (o instanceof AdditionalParams)
        {
            return (AdditionalParams)o;
        }

        if (o != null)
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(o);
            return new AdditionalParams(taggedObject.getTagNo(), taggedObject.getObject());
        }

        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getAdditionalParams()
    {
        return additionalParams;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, additionalParams);
    }

    public static class Builder
    {
        private int choice;
        private ASN1Encodable additionalParams;

        public Builder original(ButterflyParamsOriginal original)
        {
            this.additionalParams = original;
            this.choice = AdditionalParams.original;
            return this;
        }

        public Builder unified(ButterflyExpansion unified)
        {
            this.additionalParams = unified;
            this.choice = AdditionalParams.unified;
            return this;
        }

        public Builder compactUnified(ButterflyExpansion compactUnified)
        {
            this.additionalParams = compactUnified;
            this.choice = AdditionalParams.compactUnified;
            return this;
        }

        public Builder encryptionKey(PublicEncryptionKey encryptionKey)
        {
            this.additionalParams = encryptionKey;
            this.choice = AdditionalParams.encryptionKey;
            return this;
        }

        public Builder extension(ASN1OctetString extension)
        {
            this.additionalParams = extension;
            this.choice = AdditionalParams.extension;
            return this;
        }

        public AdditionalParams build()
        {
            return new AdditionalParams(choice, additionalParams);
        }

    }

}
