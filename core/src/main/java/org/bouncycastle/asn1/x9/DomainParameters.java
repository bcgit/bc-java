/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
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
 * <pre>
 *    DomainParameters ::= SEQUENCE {
 *       p                INTEGER,           -- odd prime, p=jq +1
 *       g                INTEGER,           -- generator, g
 *       q                INTEGER,           -- factor of p-1
 *       j                INTEGER OPTIONAL,  -- subgroup factor, j>= 2
 *       validationParams  ValidationParams OPTIONAL
 *    }
 * </pre>
 */
public class DomainParameters
    extends ASN1Object
{
    private ASN1Integer p, g, q, j;
    private ValidationParams validationParams;

    public static DomainParameters getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

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
        this.validationParams = validationParams;
    }

    public DomainParameters(ASN1Integer p, ASN1Integer g, ASN1Integer q, ASN1Integer j,
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

        this.p = p;
        this.g = g;
        this.q = q;
        this.j = j;
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

        if (next != null)
        {
            this.validationParams = ValidationParams.getInstance(next.toASN1Primitive());
        }
    }

    private static ASN1Encodable getNext(Enumeration e)
    {
        return e.hasMoreElements() ? (ASN1Encodable)e.nextElement() : null;
    }

    public BigInteger getP()
    {
        return this.p.getPositiveValue();
    }

    public BigInteger getG()
    {
        return this.g.getPositiveValue();
    }

    public BigInteger getQ()
    {
        return this.q.getPositiveValue();
    }

    public BigInteger getJ()
    {
        if (this.j == null)
        {
            return null;
        }

        return this.j.getPositiveValue();
    }

    public ValidationParams getValidationParams()
    {
        return this.validationParams;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
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
