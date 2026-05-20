package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * RFC 7292 - SecretBag carrier for arbitrary secret values stored in a
 * PKCS#12 SafeBag of type {@code secretBag} ({@link PKCSObjectIdentifiers#secretBag}).
 * <pre>
 *   SecretBag ::= SEQUENCE {
 *       secretTypeId BAG-TYPE.&amp;id ({SecretTypes}),
 *       secretValue  [0] EXPLICIT BAG-TYPE.&amp;Type ({SecretTypes}{&#64;secretTypeId})
 *   }
 * </pre>
 */
public class SecretBag
    extends ASN1Object
{
    private ASN1ObjectIdentifier secretTypeId;
    private ASN1Encodable secretValue;

    private SecretBag(
        ASN1Sequence seq)
    {
        this.secretTypeId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.secretValue = ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getExplicitBaseObject();
    }

    public SecretBag(
        ASN1ObjectIdentifier secretTypeId,
        ASN1Encodable secretValue)
    {
        this.secretTypeId = secretTypeId;
        this.secretValue = secretValue;
    }

    public static SecretBag getInstance(Object o)
    {
        if (o instanceof SecretBag)
        {
            return (SecretBag)o;
        }
        else if (o != null)
        {
            return new SecretBag(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1ObjectIdentifier getSecretTypeId()
    {
        return secretTypeId;
    }

    public ASN1Encodable getSecretValue()
    {
        return secretValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(secretTypeId, new DERTaggedObject(0, secretValue));
    }
}
