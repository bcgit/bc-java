package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *      id-cmc-encryptedPOP OBJECT IDENTIFIER ::= {id-cmc 9}
 *
 *      EncryptedPOP ::= SEQUENCE {
 *              request       TaggedRequest,
 *              cms             ContentInfo,
 *              thePOPAlgID     AlgorithmIdentifier,
 *              witnessAlgID    AlgorithmIdentifier,
 *              witness         OCTET STRING
 *      }
 * </pre>
 */
public class EncryptedPOP
    extends ASN1Object
{
    private final TaggedRequest request;
    private final ContentInfo cms;
    private final AlgorithmIdentifier thePOPAlgID;
    private final AlgorithmIdentifier witnessAlgID;
    private final byte[] witness;

    private EncryptedPOP(ASN1Sequence seq)
    {
        if (seq.size() != 5)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.request = TaggedRequest.getInstance(seq.getObjectAt(0));
        this.cms = ContentInfo.getInstance(seq.getObjectAt(1));
        this.thePOPAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        this.witnessAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
        this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());
    }

    public EncryptedPOP(
        TaggedRequest request,
        ContentInfo cms,
        AlgorithmIdentifier thePOPAlgID,
        AlgorithmIdentifier witnessAlgID,
        byte[] witness)
    {
        this.request = request;
        this.cms = cms;
        this.thePOPAlgID = thePOPAlgID;
        this.witnessAlgID = witnessAlgID;
        this.witness = Arrays.clone(witness);
    }

    public static EncryptedPOP getInstance(Object o)
    {
        if (o instanceof EncryptedPOP)
        {
            return (EncryptedPOP)o;
        }

        if (o != null)
        {
            return new EncryptedPOP(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public TaggedRequest getRequest()
    {
        return request;
    }

    public ContentInfo getCms()
    {
        return cms;
    }

    public AlgorithmIdentifier getThePOPAlgID()
    {
        return thePOPAlgID;
    }

    public AlgorithmIdentifier getWitnessAlgID()
    {
        return witnessAlgID;
    }

    public byte[] getWitness()
    {
        return Arrays.clone(witness);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(5);

        v.add(request);
        v.add(cms);
        v.add(thePOPAlgID);
        v.add(witnessAlgID);
        v.add(new DEROctetString(witness));

        return new DERSequence(v);
    }
}
