package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     Signature ::= CHOICE {
 *         ecdsaNistP256Signature EcdsaP256Signature,
 *         ecdsaBrainpoolP256r1Signature EcdsaP256Signature,
 *         ...
 *         ecdsaBrainpoolP384r1Signature EcdsaP384Signature
 *     }
 * </pre>
 */
public class Signature
    extends ASN1Object
    implements ASN1Choice
{
    public static final int ecdsaNistP256Signature = 0;
    public static final int ecdsaBrainpoolP256r1Signature = 1;
    public static final int ecdsaBrainpoolP384r1Signature = 2;

    private final int choice;
    private final ASN1Encodable value;

    public static Signature getInstance(Object objectAt)
    {
        if (objectAt instanceof Signature)
        {
            return (Signature)objectAt;
        }
        
        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(objectAt);
        ASN1Encodable value;

        switch (ato.getTagNo())
        {
        case ecdsaNistP256Signature:
            value = EcdsaP256Signature.getInstance(ato.getObject());
            break;
        case ecdsaBrainpoolP256r1Signature:
            value = EcdsaP256Signature.getInstance(ato.getObject());
            break;
        case ecdsaBrainpoolP384r1Signature:
            value = EcdsaP384Signature.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalStateException("unknown choice " + ato.getTagNo());
        }
        return new Signature(ato.getTagNo(), value);

    }

    public Signature(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
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
}
