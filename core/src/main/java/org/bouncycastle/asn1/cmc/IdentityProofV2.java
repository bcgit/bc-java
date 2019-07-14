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
 *      id-cmc-identityProofV2 OBJECT IDENTIFIER ::= { id-cmc 34 }
 *      identityProofV2 ::= SEQUENCE {
 *          proofAlgID       AlgorithmIdentifier,
 *          macAlgId         AlgorithmIdentifier,
 *          witness          OCTET STRING
 *      }
 * </pre>
 */
public class IdentityProofV2
    extends ASN1Object
{
    private final AlgorithmIdentifier proofAlgID;
    private final AlgorithmIdentifier macAlgId;
    private final byte[] witness;
    
    public IdentityProofV2(AlgorithmIdentifier proofAlgID, AlgorithmIdentifier macAlgId, byte[] witness)
    {
        this.proofAlgID = proofAlgID;
        this.macAlgId = macAlgId;
        this.witness = Arrays.clone(witness);
    }
        
    private IdentityProofV2(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.proofAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.macAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
    }

    public static IdentityProofV2 getInstance(Object o)
    {
        if (o instanceof IdentityProofV2)
        {
            return (IdentityProofV2)o;
        }

        if (o != null)
        {
            return new IdentityProofV2(ASN1Sequence.getInstance(o));
        }

        return null;
    }
    
    public AlgorithmIdentifier getProofAlgID()
    {
        return proofAlgID;
    }

    public AlgorithmIdentifier getMacAlgId()
    {
        return macAlgId;
    }

    public byte[] getWitness()
    {
        return Arrays.clone(witness);
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        
        v.add(proofAlgID);
        v.add(macAlgId);
        v.add(new DEROctetString(getWitness()));
        
        return new DERSequence(v);
    }
}
