package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * ButterflyParamsOriginal ::= SEQUENCE {
 * signingExpansion     ButterflyExpansion,
 * encryptionKey        PublicEncryptionKey,
 * encryptionExpansion  ButterflyExpansion
 * }
 */
public class ButterflyParamsOriginal
    extends ASN1Object
{
    private final ButterflyExpansion signingExpansion;
    private final PublicEncryptionKey encryptionKey;
    private final ButterflyExpansion encryptionExpansion;

    public ButterflyParamsOriginal(ButterflyExpansion signingExpansion,
                                   PublicEncryptionKey encryptionKey,
                                   ButterflyExpansion encryptionExpansion)
    {
        this.signingExpansion = signingExpansion;
        this.encryptionKey = encryptionKey;
        this.encryptionExpansion = encryptionExpansion;
    }

    public static ButterflyParamsOriginal getInstance(Object o)
    {
        if (o instanceof ButterflyParamsOriginal)
        {
            return (ButterflyParamsOriginal)o;
        }
        ASN1Sequence sequence = ASN1Sequence.getInstance(o);
        if (sequence.size() != 3)
        {
            throw new IllegalArgumentException("sequence must be 3 elements");
        }

        return new ButterflyParamsOriginal(
            ButterflyExpansion.getInstance(sequence.getObjectAt(0)),
            PublicEncryptionKey.getInstance(sequence.getObjectAt(1)),
            ButterflyExpansion.getInstance(sequence.getObjectAt(2))
        );
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(
            new ASN1Encodable[]{
                signingExpansion, encryptionKey, encryptionExpansion});
    }

    public ButterflyExpansion getSigningExpansion()
    {
        return signingExpansion;
    }

    public PublicEncryptionKey getEncryptionKey()
    {
        return encryptionKey;
    }

    public ButterflyExpansion getEncryptionExpansion()
    {
        return encryptionExpansion;
    }

    public static class Builder
    {
        private ButterflyExpansion signingExpansion;
        private PublicEncryptionKey encryptionKey;
        private ButterflyExpansion encryptionExpansion;

        public Builder setSigningExpansion(ButterflyExpansion signingExpansion)
        {
            this.signingExpansion = signingExpansion;
            return this;
        }

        public Builder setEncryptionKey(PublicEncryptionKey encryptionKey)
        {
            this.encryptionKey = encryptionKey;
            return this;
        }

        public Builder setEncryptionExpansion(ButterflyExpansion encryptionExpansion)
        {
            this.encryptionExpansion = encryptionExpansion;
            return this;
        }

        public ButterflyParamsOriginal build()
        {
            return new ButterflyParamsOriginal(signingExpansion, encryptionKey, encryptionExpansion);
        }

    }


}
