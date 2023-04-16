package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EciesP256EncryptedKey;

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


    private final int choice;
    private final ASN1Encodable encryptedDataEncryptionKey;

    public EncryptedDataEncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.encryptedDataEncryptionKey = value;
    }

    private EncryptedDataEncryptionKey(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (ato.getTagNo())
        {
        case eciesNistP256:
        case eciesBrainpoolP256r1:
            encryptedDataEncryptionKey = EciesP256EncryptedKey.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + ato.getTagNo());
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
            return new EncryptedDataEncryptionKey(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getEncryptedDataEncryptionKey()
    {
        return encryptedDataEncryptionKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, encryptedDataEncryptionKey);
    }

    public static EncryptedDataEncryptionKey eciesNistP256(EciesP256EncryptedKey value)
    {
        return new EncryptedDataEncryptionKey(eciesNistP256, value);
    }

    public static EncryptedDataEncryptionKey eciesBrainpoolP256r1(EciesP256EncryptedKey value)
    {
        return new EncryptedDataEncryptionKey(eciesBrainpoolP256r1, value);
    }


}
