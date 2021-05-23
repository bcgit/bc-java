package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

public class Features
    extends SignatureSubpacket
{

    /** Identifier for the modification detection feature */
    public static final byte FEATURE_MODIFICATION_DETECTION = 0x01;
    public static final byte FEATURE_AEAD_ENCRYPTED_DATA = 0x02;
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

    /**
     * Sets support for a particular feature.
     */
    private void setSupportsFeature(byte feature, boolean support)
    {
        if (feature == 0)
        {
            throw new IllegalArgumentException("feature == 0");
        }
        if (supportsFeature(feature) != support)
        {
            if (support == true)
            {
                data[0] |= feature;
            }
            else
            {
                data[0] &= ~feature;
            }
        }
    }
}
