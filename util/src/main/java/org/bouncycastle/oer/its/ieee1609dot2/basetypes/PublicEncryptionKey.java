package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * PublicEncryptionKey ::= SEQUENCE {
 * supportedSymmAlg  SymmAlgorithm,
 * publicKey         BasePublicEncryptionKey
 * }
 */
public class PublicEncryptionKey
    extends ASN1Object
{
    private final SymmAlgorithm supportedSymmAlg;
    private final BasePublicEncryptionKey basePublicEncryptionKey;

    public PublicEncryptionKey(SymmAlgorithm supportedSymmAlg, BasePublicEncryptionKey basePublicEncryptionKey)
    {
        this.supportedSymmAlg = supportedSymmAlg;
        this.basePublicEncryptionKey = basePublicEncryptionKey;
    }

    public static PublicEncryptionKey getInstance(Object o)
    {
        if (o instanceof PublicEncryptionKey)
        {
            return (PublicEncryptionKey)o;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(o);
        return new PublicEncryptionKey(
            SymmAlgorithm.getInstance(seq.getObjectAt(0)),
            BasePublicEncryptionKey.getInstance(seq.getObjectAt(1)));

    }

    public SymmAlgorithm getSupportedSymmAlg()
    {
        return supportedSymmAlg;
    }

    public BasePublicEncryptionKey getBasePublicEncryptionKey()
    {
        return basePublicEncryptionKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(supportedSymmAlg, basePublicEncryptionKey);
    }
}
