package org.bouncycastle.asn1.x9;

import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * X9.44 Diffie-Hellman domain parameters.
 * <pre>
 *    DomainParameters ::= SEQUENCE {
 *       p                INTEGER,           -- odd prime, p=jq +1
 *       g                INTEGER,           -- generator, g
 *       q                INTEGER,           -- factor of p-1
 *       j                INTEGER OPTIONAL,  -- subgroup factor, j &gt;= 2
 *       validationParams  ValidationParams OPTIONAL
 *    }
 * </pre>
 */
public class DomainParameters
    extends ASN1Object
{
    private final ASN1Integer p, g, q, j;
    private final ValidationParams validationParams;

    /**
     * Return a DomainParameters object from the passed in tagged object.
     *
     * @param obj a tagged object.
     * @param explicit true if the contents of the object is explictly tagged, false otherwise.
     * @return a DomainParameters
     */
    public static DomainParameters getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Return a DomainParameters object from the passed in object.
     *
     * @param obj an object for conversion or a byte[].
     * @return a DomainParameters
     */
    public static DomainParameters getInstance(Object obj)
    {
        if (obj instanceof DomainParameters)
        {
            return (DomainParameters)obj;
        }
        else if (obj != null)
        {
            return new DomainParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Base constructor - the full domain parameter set.
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param q specifies the prime factor of p - 1
     * @param j optionally specifies the value that satisfies the equation p = jq+1
     * @param validationParams parameters for validating these domain parameters.
     */
    public DomainParameters(BigInteger p, BigInteger g, BigInteger q, BigInteger j,
                            ValidationParams validationParams)
    {
        if (p == null)
        {
            throw new IllegalArgumentException("'p' cannot be null");
        }
        if (g == null)
        {
            throw new IllegalArgumentException("'g' cannot be null");
        }
        if (q == null)
        {
            throw new IllegalArgumentException("'q' cannot be null");
        }

        this.p = new ASN1Integer(p);
        this.g = new ASN1Integer(g);
        this.q = new ASN1Integer(q);

        if (j != null)
        {
            this.j = new ASN1Integer(j);
        }
        else
        {
            this.j = null;
        }
        this.validationParams = validationParams;
    }

    private DomainParameters(ASN1Sequence seq)
    {
        if (seq.size() < 3 || seq.size() > 5)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        Enumeration e = seq.getObjects();
        this.p = ASN1Integer.getInstance(e.nextElement());
        this.g = ASN1Integer.getInstance(e.nextElement());
        this.q = ASN1Integer.getInstance(e.nextElement());

        ASN1Encodable next = getNext(e);

        if (next != null && next instanceof ASN1Integer)
        {
            this.j = ASN1Integer.getInstance(next);
            next = getNext(e);
        }
        else
        {
            this.j = null;
        }

        if (next != null)
        {
            this.validationParams = ValidationParams.getInstance(next.toASN1Primitive());
        }
        else
        {
            this.validationParams = null;
        }
    }

    private static ASN1Encodable getNext(Enumeration e)
    {
        return e.hasMoreElements() ? (ASN1Encodable)e.nextElement() : null;
    }

    /**
     * Return the prime p defining the Galois field.
     *
     * @return the prime p.
     */
    public BigInteger getP()
    {
        return this.p.getPositiveValue();
    }

    /**
     * Return the generator of the multiplicative subgroup of order g.
     *
     * @return the generator g.
     */
    public BigInteger getG()
    {
        return this.g.getPositiveValue();
    }

    /**
     * Return q, the prime factor of p - 1
     *
     * @return q value
     */
    public BigInteger getQ()
    {
        return this.q.getPositiveValue();
    }

    /**
     * Return the value that satisfies the equation p = jq+1 (if present).
     *
     * @return j value or null.
     */
    public BigInteger getJ()
    {
        if (this.j == null)
        {
            return null;
        }

        return this.j.getPositiveValue();
    }

    /**
     * Return the validation parameters for this set (if present).
     *
     * @return validation parameters, or null if absent.
     */
    public ValidationParams getValidationParams()
    {
        return this.validationParams;
    }

    /**
     * Return an ASN.1 primitive representation of this object.
     *
     * @return a DERSequence containing the parameter values.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(this.p);
        v.add(this.g);
        v.add(this.q);

        if (this.j != null)
        {
            v.add(this.j);
        }

        if (this.validationParams != null)
        {
            v.add(this.validationParams);
        }

        return new DERSequence(v);
    }
}