package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 * EncryptedObjectStoreData ::= SEQUENCE {
 *     encryptionAlgorithm AlgorithmIdentifier
 *     encryptedContent OCTET STRING
 * }
 * </pre>
 */
public class EncryptedObjectStoreData
    extends ASN1Object
{
    private final AlgorithmIdentifier encryptionAlgorithm;
    private final ASN1OctetString encryptedContent;

    public EncryptedObjectStoreData(AlgorithmIdentifier encryptionAlgorithm, byte[] encryptedContent)
    {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.encryptedContent = new DEROctetString(encryptedContent);
    }

    private EncryptedObjectStoreData(ASN1Sequence seq)
    {
        this.encryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedContent = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static EncryptedObjectStoreData getInstance(Object o)
    {
        if (o instanceof EncryptedObjectStoreData)
        {
            return (EncryptedObjectStoreData)o;
        }
        else if (o != null)
        {
            return new EncryptedObjectStoreData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1OctetString getEncryptedContent()
    {
        return encryptedContent;
    }

    public AlgorithmIdentifier getEncryptionAlgorithm()
    {
        return encryptionAlgorithm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(encryptionAlgorithm);
        v.add(encryptedContent);

        return new DERSequence(v);
    }
}