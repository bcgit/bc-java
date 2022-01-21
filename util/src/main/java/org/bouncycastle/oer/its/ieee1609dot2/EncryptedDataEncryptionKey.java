package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * EncryptedDataEncryptionKey ::= CHOICE {
 * eciesNistP256         EciesP256EncryptedKey,
 * eciesBrainpoolP256r1  EciesP256EncryptedKey,
 * ...
 * }
 */
public class EncryptedDataEncryptionKey
    extends ASN1Object
    implements ASN1Choice
{
    public static final int eciesNistP256 = 0;
    public static final int eciesBrainpoolP256r1 = 1;
    public static final int extension = 2;

    private final int choice;
    private final ASN1Encodable value;

    public EncryptedDataEncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    private EncryptedDataEncryptionKey(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (ato.getTagNo())
        {
        case eciesNistP256:
        case eciesBrainpoolP256r1:
            value = ato.getObject();
            break;
        default:
            throw new IllegalStateException("unknown choice " + ato.getTagNo());
        }
    }

    public static EncryptedDataEncryptionKey getInstance(Object o)
    {
        if (o instanceof EncryptedDataEncryptionKey)
        {
            return (EncryptedDataEncryptionKey)o;
        }

        if (o != null)
        {
            return new EncryptedDataEncryptionKey(ASN1TaggedObject.getInstance(o));
        }

        return null;

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
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

        public EncryptedDataEncryptionKey createEncryptedDataEncryptionKey()
        {
            return new EncryptedDataEncryptionKey(choice, value);
        }
    }

}
