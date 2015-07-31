package org.bouncycastle.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Builder and holder class for preparing SP 800-56A compliant OtherInfo. The data is ultimately encoded as a DER SEQUENCE.
 * Empty octet strings are used to represent nulls in compulsory fields.
 */
public class DEROtherInfo
{
    /**
     * Builder to create OtherInfo
     */
    public static final class Builder
    {
        private final AlgorithmIdentifier algorithmID;
        private final ASN1OctetString partyUVInfo;
        private final ASN1OctetString partyVInfo;

        private ASN1TaggedObject suppPubInfo;
        private ASN1TaggedObject suppPrivInfo;

        /**
         * Create a basic builder with just the compulsory fields.
         *
         * @param algorithmID the algorithm associated with this invocation of the KDF.
         * @param partyUInfo  sender party info.
         * @param partyVInfo  receiver party info.
         */
        public Builder(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo)
        {
            this.algorithmID = algorithmID;
            this.partyUVInfo = DerUtil.getOctetString(partyUInfo);
            this.partyVInfo = DerUtil.getOctetString(partyVInfo);
        }

        /**
         * Add optional supplementary public info (DER tagged, implicit, 0).
         *
         * @param suppPubInfo supplementary public info.
         * @return  the current builder instance.
         */
        public Builder withSuppPubInfo(byte[] suppPubInfo)
        {
            this.suppPubInfo = new DERTaggedObject(false, 0, DerUtil.getOctetString(suppPubInfo));

            return this;
        }

        /**
         * Add optional supplementary private info (DER tagged, implicit, 1).
         *
         * @param suppPrivInfo supplementary private info.
         * @return the current builder instance.
         */
        public Builder withSuppPrivInfo(byte[] suppPrivInfo)
        {
            this.suppPrivInfo = new DERTaggedObject(false, 1, DerUtil.getOctetString(suppPrivInfo));

            return this;
        }

        /**
         * Build the KTSOtherInfo.
         *
         * @return an KTSOtherInfo containing the data.
         */
        public DEROtherInfo build()
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(algorithmID);
            v.add(partyUVInfo);
            v.add(partyVInfo);

            if (suppPubInfo != null)
            {
                v.add(suppPubInfo);
            }

            if (suppPrivInfo != null)
            {
                v.add(suppPrivInfo);
            }

            return new DEROtherInfo(new DERSequence(v));
        }
    }

    private final DERSequence sequence;

    private DEROtherInfo(DERSequence sequence)
    {
        this.sequence = sequence;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return sequence.getEncoded();
    }
}
