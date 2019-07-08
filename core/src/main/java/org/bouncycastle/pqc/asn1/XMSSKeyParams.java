package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * XMSSKeyParams
 * <pre>
 *     XMSSKeyParams ::= SEQUENCE {
 *     version INTEGER -- 0
 *     height INTEGER
 *     treeDigest AlgorithmIdentifier
 * }
 * </pre>
 */
public class XMSSKeyParams
    extends ASN1Object
{
    private final ASN1Integer version;
    private final int height;
    private final AlgorithmIdentifier treeDigest;

    public XMSSKeyParams(int height, AlgorithmIdentifier treeDigest)
    {
        this.version = new ASN1Integer(0);
        this.height = height;
        this.treeDigest = treeDigest;
    }

    private XMSSKeyParams(ASN1Sequence sequence)
    {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact();
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(2));
    }

    public static XMSSKeyParams getInstance(Object o)
    {
        if (o instanceof XMSSKeyParams)
        {
            return (XMSSKeyParams)o;
        }
        else if (o != null)
        {
            return new XMSSKeyParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getHeight()
    {
        return height;
    }

    public AlgorithmIdentifier getTreeDigest()
    {
        return treeDigest;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(new ASN1Integer(height));
        v.add(treeDigest);

        return new DERSequence(v);
    }
}
