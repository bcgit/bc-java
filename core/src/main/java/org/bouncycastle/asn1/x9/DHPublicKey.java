package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * X9.42 definition of a DHPublicKey
 * <pre>
 *     DHPublicKey ::= INTEGER
 * </pre>
 */
public class DHPublicKey
    extends ASN1Object
{
    private ASN1Integer y;

    /**
     * Return a DHPublicKey from the passed in tagged object.
     *
     * @param obj a tagged object.
     * @param explicit true if the contents of the object is explictly tagged, false otherwise.
     * @return a DHPublicKey
     */
    public static DHPublicKey getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Integer.getInstance(obj, explicit));
    }

    /**
     * Return a DHPublicKey from the passed in object.
     *
     * @param obj an object for conversion or a byte[].
     * @return a DHPublicKey
     */
    public static DHPublicKey getInstance(Object obj)
    {
        if (obj == null || obj instanceof DHPublicKey)
        {
            return (DHPublicKey)obj;
        }

        if (obj instanceof ASN1Integer)
        {
            return new DHPublicKey((ASN1Integer)obj);
        }

        throw new IllegalArgumentException("Invalid DHPublicKey: " + obj.getClass().getName());
    }

    private DHPublicKey(ASN1Integer y)
    {
        if (y == null)
        {
            throw new IllegalArgumentException("'y' cannot be null");
        }

        this.y = y;
    }

    /**
     * Base constructor.
     *
     * @param y the public value Y.
     */
    public DHPublicKey(BigInteger y)
    {
        if (y == null)
        {
            throw new IllegalArgumentException("'y' cannot be null");
        }

        this.y = new ASN1Integer(y);
    }

    /**
     * Return the public value Y for the key.
     *
     * @return the Y value.
     */
    public BigInteger getY()
    {
        return this.y.getPositiveValue();
    }

    /**
     * Return an ASN.1 primitive representation of this object.
     *
     * @return an ASN1Integer.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return this.y;
    }
}