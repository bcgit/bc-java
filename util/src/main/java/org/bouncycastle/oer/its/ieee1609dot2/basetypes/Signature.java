package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
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
    private final ASN1Encodable signature;

    public Signature(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.signature = value;
    }

    public static Signature ecdsaNistP256Signature(EcdsaP256Signature v)
    {
        return new Signature(ecdsaNistP256Signature, v);
    }

    public static Signature ecdsaBrainpoolP256r1Signature(EcdsaP256Signature v)
    {
        return new Signature(ecdsaBrainpoolP256r1Signature, v);
    }

    public static Signature ecdsaBrainpoolP384r1Signature(EcdsaP384Signature v)
    {
        return new Signature(ecdsaBrainpoolP384r1Signature, v);
    }



    private Signature(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (choice)
        {
        case ecdsaNistP256Signature:
        case ecdsaBrainpoolP256r1Signature:
            signature = EcdsaP256Signature.getInstance(ato.getExplicitBaseObject());
            break;
        case ecdsaBrainpoolP384r1Signature:
            signature = EcdsaP384Signature.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + ato.getTagNo());
        }

    }


    public static Signature getInstance(Object objectAt)
    {
        if (objectAt instanceof Signature)
        {
            return (Signature)objectAt;
        }

        if (objectAt != null)
        {
            return new Signature(ASN1TaggedObject.getInstance(objectAt, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getSignature()
    {
        return signature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, signature);
    }


}
