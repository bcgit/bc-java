package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *      id-cmc-decryptedPOP OBJECT IDENTIFIER ::= {id-cmc 10}
 *
 *       DecryptedPOP ::= SEQUENCE {
 *            bodyPartID      BodyPartID,
 *            thePOPAlgID     AlgorithmIdentifier,
 *            thePOP          OCTET STRING
 *       }
 * </pre>
 */
public class DecryptedPOP
    extends ASN1Object
{
    private final BodyPartID bodyPartID;
    private final AlgorithmIdentifier thePOPAlgID;
    private final byte[] thePOP;

    public DecryptedPOP(BodyPartID bodyPartID, AlgorithmIdentifier thePOPAlgID, byte[] thePOP)
    {
        this.bodyPartID = bodyPartID;
        this.thePOPAlgID = thePOPAlgID;
        this.thePOP = Arrays.clone(thePOP);
    }

    private DecryptedPOP(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
        this.thePOPAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.thePOP = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
    }


    public static DecryptedPOP getInstance(Object o)
    {
        if (o instanceof DecryptedPOP)
        {
            return (DecryptedPOP)o;
        }

        if (o != null)
        {
            return new DecryptedPOP(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public BodyPartID getBodyPartID()
    {
        return bodyPartID;
    }

    public AlgorithmIdentifier getThePOPAlgID()
    {
        return thePOPAlgID;
    }

    public byte[] getThePOP()
    {
        return Arrays.clone(thePOP);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(bodyPartID);
        v.add(thePOPAlgID);
        v.add(new DEROctetString(thePOP));

        return new DERSequence(v);
    }
}
