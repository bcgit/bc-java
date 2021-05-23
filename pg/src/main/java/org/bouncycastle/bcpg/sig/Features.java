package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

public class Features
    extends SignatureSubpacket
{
    /** Identifier for the Modification Detection (packets 18 and 19) */
    public static final byte FEATURE_MODIFICATION_DETECTION = 0x01;
    /** Identifier for the AEAD Encrypted Data Packet (packet 20) and version 5
     Symmetric-Key Encrypted Session Key Packets (packet 3) */
    public static final byte FEATURE_AEAD_ENCRYPTED_DATA = 0x02;
    /** Identifier for the Version 5 Public-Key Packet format and corresponding new
       fingerprint format */
    public static final byte FEATURE_VERSION_5_PUBLIC_KEY = 0x04;

    private static final byte[] featureToByteArray(byte feature)
    {
        byte[] data = new byte[1];
        data[0] = feature;
        return data;
    }

    public Features(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.FEATURES, critical, isLongLength, data);
    }

    public Features(boolean critical, byte features)
    {
        super(SignatureSubpacketTags.FEATURES, critical, false, featureToByteArray(features));
    }

    public Features(boolean critical, int features)
    {
        super(SignatureSubpacketTags.FEATURES, critical, false, featureToByteArray((byte)features));
    }

    /**
     * Returns if modification detection is supported.
     */
    public boolean supportsModificationDetection()
    {
        return supportsFeature(FEATURE_MODIFICATION_DETECTION);
    }

    /**
     * Returns if a particular feature is supported.
     */
    public boolean supportsFeature(byte feature)
    {
        return (data[0] & feature) != 0;
    }
}
