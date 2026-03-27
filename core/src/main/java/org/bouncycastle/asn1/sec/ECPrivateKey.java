package org.bouncycastle.asn1.sec;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.BigIntegers;

/**
 * the elliptic curve private key object from SEC 1
 */
public class ECPrivateKey
    extends ASN1Object
{
    public static ECPrivateKey getInstance(Object obj)
    {
        if (obj instanceof ECPrivateKey)
        {
            return (ECPrivateKey)obj;
        }

        if (obj != null)
        {
            return new ECPrivateKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ECPrivateKey getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new ECPrivateKey(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static ECPrivateKey getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new ECPrivateKey(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private final ASN1Sequence seq;

    private ECPrivateKey(ASN1Sequence seq)
    {
        this.seq = seq;
    }

    /**
     * Base constructor.
     *
     * @param orderBitLength the bitLength of the order of the curve.
     * @param key the private key value.
     */
    public ECPrivateKey(int orderBitLength, BigInteger key)
    {
        byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

        seq = new DERSequence(ASN1Integer.ONE, new DEROctetString(bytes));
    }

    public ECPrivateKey(int orderBitLength, BigInteger key, ASN1Encodable parameters)
    {
        this(orderBitLength, key, null, parameters);
    }

    public ECPrivateKey(int orderBitLength, BigInteger key, ASN1BitString publicKey, ASN1Encodable parameters)
    {
        byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);

        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(ASN1Integer.ONE);
        v.add(new DEROctetString(bytes));

        if (parameters != null)
        {
            v.add(new DERTaggedObject(true, 0, parameters));
        }

        if (publicKey != null)
        {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }

        seq = new DERSequence(v);
    }

    public ECPrivateKey(ASN1OctetString privateKey, ASN1Encodable parameters, ASN1BitString publicKey)
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(ASN1Integer.ONE);
        v.add(privateKey);

        if (parameters != null)
        {
            v.add(new DERTaggedObject(true, 0, parameters));
        }

        if (publicKey != null)
        {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }

        seq = new DERSequence(v);
    }

    public BigInteger getKey()
    {
        return new BigInteger(1, getPrivateKey().getOctets());
    }

    public ASN1OctetString getPrivateKey()
    {
        return (ASN1OctetString)seq.getObjectAt(1);
    }

    public ASN1BitString getPublicKey()
    {
        return (ASN1BitString)getObjectInTag(1, BERTags.BIT_STRING);
    }

    public ASN1Object getParametersObject()
    {
        return getObjectInTag(0, -1);
    }

    private ASN1Object getObjectInTag(int tagNo, int baseTagNo)
    {
        for (int i = 0, count = seq.size(); i < count; ++i)
        {
            ASN1Encodable element = seq.getObjectAt(i);
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getContextOptional(element, tagNo);
            if (taggedObject != null)
            {
                return baseTagNo < 0
                    ? taggedObject.getExplicitBaseObject().toASN1Primitive()
                    : taggedObject.getBaseUniversal(true, baseTagNo);
            }
        }
        return null;
    }

    /**
     * ECPrivateKey ::= SEQUENCE {
     *     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
     *     privateKey OCTET STRING,
     *     parameters [0] Parameters OPTIONAL,
     *     publicKey [1] BIT STRING OPTIONAL }
     */
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
