package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Builder and holder class for preparing SP 800-56A compliant MacData. Elements in the data are encoded
 * as DER objects with empty octet strings used to represent nulls in compulsory fields.
 */
public final class DERMacData
{
    public static class Type
    {
        public static final Type UNILATERALU = new Type("KC_1_U", 0);
        public static final Type UNILATERALV = new Type("KC_1_V", 1);
        public static final Type BILATERALU = new Type("KC_2_U", 2);
        public static final Type BILATERALV = new Type("KC_2_V", 3);

        private final String enc;
        private final int ordinal;

        Type(String enc, int ordinal)
        {
            this.enc = enc;
            this.ordinal = ordinal;
        }

        public byte[] getHeader()
        {
            return Strings.toByteArray(enc);
        }
    }

    /**
     * Builder to create OtherInfo
     */
    public static final class Builder
    {
        private final Type type;

        private ASN1OctetString idU;
        private ASN1OctetString idV;
        private ASN1OctetString ephemDataU;
        private ASN1OctetString ephemDataV;
        private byte[] text;

        /**
         * Create a basic builder with just the compulsory fields.
         *
         * @param type the MAC header
         * @param idU  sender party ID.
         * @param idV  receiver party ID.
         * @param ephemDataU ephemeral data from sender.
         * @param ephemDataV ephemeral data from receiver.
         */
        public Builder(Type type, byte[] idU, byte[] idV, byte[] ephemDataU, byte[] ephemDataV)
        {
            this.type = type;
            this.idU = DerUtil.getOctetString(idU);
            this.idV = DerUtil.getOctetString(idV);
            this.ephemDataU = DerUtil.getOctetString(ephemDataU);
            this.ephemDataV = DerUtil.getOctetString(ephemDataV);
        }

        /**
         * Add optional text.
         *
         * @param text optional agreed text to add to the MAC.
         * @return the current builder instance.
         */
        public Builder withText(byte[] text)
        {
            this.text = DerUtil.toByteArray(new DERTaggedObject(false, 0, DerUtil.getOctetString(text)));

            return this;
        }

        public DERMacData build()
        {
            switch (type.ordinal)
            {
            case 0: // UNILATERALU:
            case 2: // BILATERALU:
                return new DERMacData(concatenate(type.getHeader(),
                                DerUtil.toByteArray(idU), DerUtil.toByteArray(idV),
                                DerUtil.toByteArray(ephemDataU), DerUtil.toByteArray(ephemDataV), text));
            case 1: // UNILATERALV:
            case 3: // BILATERALV:
                return new DERMacData(concatenate(type.getHeader(),
                                DerUtil.toByteArray(idV), DerUtil.toByteArray(idU),
                                DerUtil.toByteArray(ephemDataV), DerUtil.toByteArray(ephemDataU), text));
            }

            throw new IllegalStateException("Unknown type encountered in build");   // should never happen
        }

        private byte[] concatenate(byte[] header, byte[] id1, byte[] id2, byte[] ed1, byte[] ed2, byte[] text)
        {
            return Arrays.concatenate(Arrays.concatenate(header, id1, id2), Arrays.concatenate(ed1, ed2, text));
        }
    }

    private final byte[] macData;

    private DERMacData(byte[] macData)
    {
        this.macData = macData;
    }

    public byte[] getMacData()
    {
        return Arrays.clone(macData);
    }
}
