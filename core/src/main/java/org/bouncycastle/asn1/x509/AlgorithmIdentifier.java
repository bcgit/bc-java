package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class AlgorithmIdentifier
    extends ASN1Object
{
    public static AlgorithmIdentifier getInstance(Object obj)
    {
        if (obj instanceof AlgorithmIdentifier)
        {
            return (AlgorithmIdentifier)obj;
        }
        else if (obj != null)
        {
            return new AlgorithmIdentifier(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static AlgorithmIdentifier getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new AlgorithmIdentifier(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static AlgorithmIdentifier getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new AlgorithmIdentifier(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private ASN1ObjectIdentifier algorithm;
    private ASN1Encodable       parameters;

    public AlgorithmIdentifier(
        ASN1ObjectIdentifier algorithm)
    {
        this.algorithm = algorithm;
    }

    public AlgorithmIdentifier(
        ASN1ObjectIdentifier algorithm,
        ASN1Encodable           parameters)
    {
        this.algorithm = algorithm;
        this.parameters = parameters;
    }

    private AlgorithmIdentifier(
        ASN1Sequence   seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }
        
        algorithm = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            parameters = seq.getObjectAt(1);
        }
        else
        {
            parameters = null;
        }
    }

    public ASN1ObjectIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public ASN1Encodable getParameters()
    {
        return parameters;
    }

    /**
     * Return true if two algorithm identifiers name the same algorithm carrying the same
     * parameters, counting an absent parameters field and an explicit {@code NULL} as the same
     * thing - both say "this algorithm takes no parameters", they simply say it differently.
     * <p>
     * The two encodings are both in wide use for the SHA-2 digests, and
     * <a href="https://www.rfc-editor.org/rfc/rfc5754#section-2">RFC 5754 sec. 2</a> requires a
     * receiver to take either: <em>"Implementations MUST accept SHA2 AlgorithmIdentifiers with
     * absent parameters. Implementations MUST accept SHA2 AlgorithmIdentifiers with NULL
     * parameters."</em> - while requiring that they be <em>generated</em> with the parameters
     * absent. {@link #equals(Object)} compares the encodings and so separates them, which is right
     * for a map key but wrong for deciding whether a peer named the algorithm we expected.
     * <p>
     * Note this only equates absent with {@code NULL}; an identifier carrying an actual parameter
     * structure is never equivalent to one carrying none.
     *
     * @param a an algorithm identifier, may be null.
     * @param b an algorithm identifier, may be null.
     * @return true if the two name the same algorithm with the same parameters.
     */
    public static boolean areEquivalent(AlgorithmIdentifier a, AlgorithmIdentifier b)
    {
        if (a == b)
        {
            return true;
        }
        if (a == null || b == null)
        {
            return false;
        }
        if (!a.getAlgorithm().equals(b.getAlgorithm()))
        {
            return false;
        }

        ASN1Encodable pa = a.getParameters(), pb = b.getParameters();

        if (isAbsentOrNull(pa))
        {
            return isAbsentOrNull(pb);
        }

        return pa.equals(pb);
    }

    private static boolean isAbsentOrNull(ASN1Encodable parameters)
    {
        return parameters == null || parameters instanceof ASN1Null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *      AlgorithmIdentifier ::= SEQUENCE {
     *                            algorithm OBJECT IDENTIFIER,
     *                            parameters ANY DEFINED BY algorithm OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algorithm);

        if (parameters != null)
        {
            v.add(parameters);
        }

        return new DERSequence(v);
    }
}
