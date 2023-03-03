package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * X.509 Section 9.8.3.
 * <br/>
 * This extension may be used as a public-key certificate extension, a CRL extension or an AVL extension. It shall contain
 * the algorithm identifier for the alternative digital signature algorithm used by the signer when creating an alternative
 * digital signature and by the relying party when validating the alternative digital signature.
 * <pre>
 * altSignatureAlgorithm EXTENSION ::= {
 *     SYNTAX AltSignatureAlgorithm
 *     IDENTIFIED BY id-ce-altSignatureAlgorithm }
 *
 * AltSignatureAlgorithm ::= AlgorithmIdentifier{{SupportedAlgorithms}}
 * </pre>
 * When the altSignatureAlgorithm extension is included in a particular value that is an instance of a data type that
 * supports extensions, the altSignatureValue extension shall also be included.
 * <br/>
 * NOTE 1 – By having a separate altSignatureAlgorithm extension, instead of having it combined with the
 * altSignatureValue extension, the alternative digital signature algorithm is protected by the alternative signature.
 * This extension may be flagged either as critical or as non-critical.
 * <br/>
 * NOTE 2 – It is recommended that it be flagged as non-critical. Flagging it as critical would require all relying parties to understand
 * the extension and the alternative public-key algorithms
 */
public class AltSignatureAlgorithm
    extends ASN1Object
{
    private final AlgorithmIdentifier algorithm;

    public static AltSignatureAlgorithm getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(AlgorithmIdentifier.getInstance(obj, explicit));
    }

    public static AltSignatureAlgorithm getInstance(
        Object obj)
    {
        if (obj instanceof AltSignatureAlgorithm)
        {
            return (AltSignatureAlgorithm)obj;
        }
        else if (obj != null)
        {
            return new AltSignatureAlgorithm(AlgorithmIdentifier.getInstance(obj));
        }

        return null;
    }

    public static AltSignatureAlgorithm fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.altSignatureAlgorithm));
    }

    public AltSignatureAlgorithm(AlgorithmIdentifier algorithm)
    {
        this.algorithm = algorithm;
    }

    public AltSignatureAlgorithm(ASN1ObjectIdentifier algorithm)
    {
        this(algorithm, null);
    }

    public AltSignatureAlgorithm(ASN1ObjectIdentifier algorithm, ASN1Encodable parameters)
    {
        this.algorithm = new AlgorithmIdentifier(algorithm, parameters);
    }

    /**
     * Return the algorithm identifier representing the alternate signature algorithm
     * used to generate the alternate signature algorithm value extension.
     *
     * @return alternate signature algorithm identifier.
     */
    public AlgorithmIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return algorithm.toASN1Primitive();
    }
}
