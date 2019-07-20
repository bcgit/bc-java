package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 * SignatureCheck ::= SEQUENCE {
 *        signatureAlgorithm   AlgorithmIdentifier,
 *        certificates         [0] EXPLICIT Certificates OPTIONAL,
 *        signatureValue       BIT STRING
 * }
 *
 * Certificates ::= SEQUENCE OF Certificate
 * </pre>
 */
public class SignatureCheck
    extends ASN1Object
{
    private final AlgorithmIdentifier signatureAlgorithm;
    private final ASN1Sequence certificates;
    private final ASN1BitString signatureValue;

    public SignatureCheck(AlgorithmIdentifier signatureAlgorithm, byte[] signature)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.certificates = null;
        this.signatureValue = new DERBitString(Arrays.clone(signature));
    }

    public SignatureCheck(AlgorithmIdentifier signatureAlgorithm, Certificate[] certificates, byte[] signature)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.certificates = new DERSequence(certificates);
        this.signatureValue = new DERBitString(Arrays.clone(signature));
    }

    private SignatureCheck(ASN1Sequence seq)
    {
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        int index = 1;
        if (seq.getObjectAt(1) instanceof ASN1TaggedObject)
        {
            this.certificates = ASN1Sequence.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(index++)).getObject());
        }
        else
        {
            this.certificates = null;
        }
        this.signatureValue = DERBitString.getInstance(seq.getObjectAt(index));
    }

    public static SignatureCheck getInstance(Object o)
    {
        if (o instanceof SignatureCheck)
        {
            return (SignatureCheck)o;
        }
        else if (o != null)
        {
            return new SignatureCheck(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1BitString getSignature()
    {
        return new DERBitString(signatureValue.getBytes(), signatureValue.getPadBits());
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public Certificate[] getCertificates()
    {
        if (certificates == null)
        {
            return null;
        }
        
        Certificate[] certs = new Certificate[certificates.size()];

        for (int i = 0; i != certs.length; i++)
        {
            certs[i] = Certificate.getInstance(certificates.getObjectAt(i));
        }

        return certs;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(signatureAlgorithm);
        if (certificates != null)
        {
            v.add(new DERTaggedObject(0, certificates));
        }
        v.add(signatureValue);

        return new DERSequence(v);
    }
}
