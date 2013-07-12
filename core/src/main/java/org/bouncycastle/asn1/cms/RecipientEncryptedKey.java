package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * <pre>
 * RecipientEncryptedKey ::= SEQUENCE {
 *     rid KeyAgreeRecipientIdentifier,
 *     encryptedKey EncryptedKey
 * }
 * </pre>
 */

public class RecipientEncryptedKey
    extends ASN1Object
{
    private KeyAgreeRecipientIdentifier identifier;
    private ASN1OctetString encryptedKey;

    private RecipientEncryptedKey(
        ASN1Sequence seq)
    {
        identifier = KeyAgreeRecipientIdentifier.getInstance(seq.getObjectAt(0));
        encryptedKey = (ASN1OctetString)seq.getObjectAt(1);
    }
    
    /**
     * return an RecipientEncryptedKey object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static RecipientEncryptedKey getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * return a RecipientEncryptedKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null -> null
     * <li> {@link RecipientEncryptedKey} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence ASN1Sequence} input formats with RecipientEncryptedKey structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static RecipientEncryptedKey getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof RecipientEncryptedKey)
        {
            return (RecipientEncryptedKey)obj;
        }
        
        if (obj instanceof ASN1Sequence)
        {
            return new RecipientEncryptedKey((ASN1Sequence)obj);
        }
        
        throw new IllegalArgumentException("Invalid RecipientEncryptedKey: " + obj.getClass().getName());
    } 

    public RecipientEncryptedKey(
        KeyAgreeRecipientIdentifier id,
        ASN1OctetString             encryptedKey)
    {
        this.identifier = id;
        this.encryptedKey = encryptedKey;
    }

    public KeyAgreeRecipientIdentifier getIdentifier()
    {
        return identifier;
    }

    public ASN1OctetString getEncryptedKey()
    {
        return encryptedKey;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(identifier);
        v.add(encryptedKey);

        return new DERSequence(v);
    }
}
