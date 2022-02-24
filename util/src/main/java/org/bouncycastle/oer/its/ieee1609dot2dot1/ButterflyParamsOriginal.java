package org.bouncycastle.oer.its.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;

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

    private ButterflyParamsOriginal(ASN1Sequence sequence)
    {
        if (sequence.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }

        signingExpansion = ButterflyExpansion.getInstance(sequence.getObjectAt(0));
        encryptionKey = PublicEncryptionKey.getInstance(sequence.getObjectAt(1));
        encryptionExpansion = ButterflyExpansion.getInstance(sequence.getObjectAt(2));
    }


    public static ButterflyParamsOriginal getInstance(Object o)
    {
        if (o instanceof ButterflyParamsOriginal)
        {
            return (ButterflyParamsOriginal)o;
        }
        if (o != null)
        {
            return new ButterflyParamsOriginal(ASN1Sequence.getInstance(o));
        }

        return null;
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

        public ButterflyParamsOriginal createButterflyParamsOriginal()
        {
            return new ButterflyParamsOriginal(signingExpansion, encryptionKey, encryptionExpansion);
        }

    }


}
