package org.bouncycastle.oer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;

public abstract class SwitchIndexer
{
    public abstract ASN1Encodable get(int index);

    public static class Asn1SequenceIndexer
        extends SwitchIndexer
    {

        private final ASN1Sequence sequence;

        public Asn1SequenceIndexer(ASN1Sequence sequence)
        {
            this.sequence = sequence;
        }

        @Override
        public ASN1Encodable get(int index)
        {
            return sequence.getObjectAt(index);
        }
    }

    public static class Asn1EncodableVectorIndexer
        extends SwitchIndexer
    {
        private final ASN1EncodableVector asn1EncodableVector;

        public Asn1EncodableVectorIndexer(ASN1EncodableVector asn1EncodableVector)
        {
            this.asn1EncodableVector = asn1EncodableVector;
        }

        @Override
        public ASN1Encodable get(int index)
        {
            return asn1EncodableVector.get(index);
        }
    }

    public static class FixedValueIndexer
        extends SwitchIndexer
    {
        private final ASN1Encodable returnValue;

        public FixedValueIndexer(ASN1Encodable returnValue)
        {
            this.returnValue = returnValue;
        }

        @Override
        public ASN1Encodable get(int index)
        {
            return returnValue;
        }
    }

}
