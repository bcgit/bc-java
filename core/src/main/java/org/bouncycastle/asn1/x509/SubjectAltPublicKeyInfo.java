package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * X.509 Section 9.8.2.
 * <br/>
 * This public-key certificate extension, when present, shall contain the subject’s alternative public key information
 * <pre>
 * subjectAltPublicKeyInfo EXTENSION ::= {
 *      SYNTAX SubjectAltPublicKeyInfo
 *      IDENTIFIED BY id-ce-subjectAltPublicKeyInfo }
 *
 * SubjectAltPublicKeyInfo ::= SEQUENCE {
 *     algorithm AlgorithmIdentifier{{SupportedAlgorithms}},
 *     subjectAltPublicKey BIT STRING }
 * </pre>
 * The SubjectAltPublicKeyInfo data type has the following components:
 * <ul>
 * <li>the algorithm subcomponent, which shall hold the algorithm that this public key is an instance of</li>
 * <li>the subjectAltPublicKey subcomponent, which shall hold the alternative public key</li>
 * </ul>
 * This extension may be flagged as critical or as non-critical.
 * <br/>
 * NOTE – It is recommended that it be flagged as non-critical. Flagging it as critical would require relying parties to understand this
 * extension and the alternative public-key algorithm.
 */
public class SubjectAltPublicKeyInfo
    extends ASN1Object
{
    private AlgorithmIdentifier algorithm;
    private ASN1BitString subjectAltPublicKey;

    public static SubjectAltPublicKeyInfo getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SubjectAltPublicKeyInfo getInstance(
        Object obj)
    {
        if (obj instanceof SubjectAltPublicKeyInfo)
        {
            return (SubjectAltPublicKeyInfo)obj;
        }
        else if (obj != null)
        {
            return new SubjectAltPublicKeyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static SubjectAltPublicKeyInfo fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.subjectAltPublicKeyInfo));
    }

    private SubjectAltPublicKeyInfo(ASN1Sequence s)
    {
        if (s.size() != 2)
        {
            throw new IllegalArgumentException("extension should contain only 2 elements");
        }
        algorithm = AlgorithmIdentifier.getInstance(s.getObjectAt(0));
        subjectAltPublicKey = ASN1BitString.getInstance(s.getObjectAt(1));
    }

    public SubjectAltPublicKeyInfo(AlgorithmIdentifier algorithm, ASN1BitString subjectAltPublicKey)
    {
        this.algorithm = algorithm;
        this.subjectAltPublicKey = subjectAltPublicKey;
    }

    public SubjectAltPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        this.algorithm = subjectPublicKeyInfo.getAlgorithm();
        this.subjectAltPublicKey = subjectPublicKeyInfo.getPublicKeyData();
    }

    public AlgorithmIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public ASN1BitString getSubjectAltPublicKey()
    {
        return subjectAltPublicKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(algorithm);
        v.add(subjectAltPublicKey);

        return new DERSequence(v);
    }
}
