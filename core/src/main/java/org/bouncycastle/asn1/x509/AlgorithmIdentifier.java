package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class AlgorithmIdentifier
    extends ASN1Object
{
    private ASN1ObjectIdentifier algorithm;
    private ASN1Encodable       parameters;

    public static AlgorithmIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    public static AlgorithmIdentifier getInstance(
        Object  obj)
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
