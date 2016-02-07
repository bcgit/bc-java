package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SPHINCS256KeyParams
    extends ASN1Object
{
    private final ASN1Integer version;
    private final AlgorithmIdentifier treeHash;

    public SPHINCS256KeyParams(AlgorithmIdentifier treeHash)
    {
        this.version = new ASN1Integer(0);
        this.treeHash = treeHash;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(treeHash);

        return new DERSequence(v);
    }
}
