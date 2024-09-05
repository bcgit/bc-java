package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * This is a deprecated LibrePGP signature subpacket with encryption mode numbers to indicate which modes
 * the key holder prefers to use with OCB Encrypted Data Packets ({@link org.bouncycastle.bcpg.AEADEncDataPacket}).
 *  Implementations SHOULD ignore this subpacket and assume {@link org.bouncycastle.bcpg.AEADAlgorithmTags#OCB}.
 */
public class LibrePGPPreferredEncryptionModes
        extends PreferredAlgorithms
{

    public LibrePGPPreferredEncryptionModes(boolean isCritical, int[] encryptionModes)
    {
        this(isCritical, false, intToByteArray(encryptionModes));
    }

    public LibrePGPPreferredEncryptionModes(boolean critical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.LIBREPGP_PREFERRED_ENCRYPTION_MODES, critical, isLongLength, data);
    }
}
