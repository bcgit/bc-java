package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *  CMSORIforKEMOtherInfo ::= SEQUENCE {
 *     wrap KeyEncryptionAlgorithmIdentifier,
 *     kekLength INTEGER (1..MAX),
 *     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL
 *   }
 * </pre>
 */
public class CMSORIforKEMOtherInfo
    extends ASN1Object
{
    private final AlgorithmIdentifier wrap;
    private final int kekLength;

    public CMSORIforKEMOtherInfo(AlgorithmIdentifier wrap, int kekLength)
    {
        this.wrap = wrap;
        this.kekLength = kekLength;
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(wrap);
        v.add(new ASN1Integer(kekLength));

        return new DERSequence(v);
    }
}
