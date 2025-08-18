package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;

/**
 * Encryption Mode.
 */
public enum EncryptedDataPacketType
{
    /**
     * Symmetrically-Encrypted Data packet.
     * This method is deprecated, as it does not protect against malleability.
     *
     * @deprecated
     */
    @Deprecated
    SED, // deprecated
    /**
     * Symmetrically-Encrypted-Integrity-Protected Data packet version 1.
     * This method protects the message using symmetric encryption as specified in RFC4880.
     * Support for this encryption mode is signalled using
     * {@link org.bouncycastle.bcpg.sig.Features#FEATURE_MODIFICATION_DETECTION}.
     */
    SEIPDv1, // v4

    /**
     * Symmetrically-Encrypted-Integrity-Protected Data packet version 2.
     * This method protects the message using an AEAD encryption scheme specified in RFC9580.
     * Support for this feature is signalled using {@link org.bouncycastle.bcpg.sig.Features#FEATURE_SEIPD_V2}.
     */
    SEIPDv2, // v6

    /**
     * LibrePGP OCB-Encrypted Data packet.
     * This method protects the message using an AEAD encryption scheme specified in LibrePGP.
     * Support for this feature is signalled using {@link org.bouncycastle.bcpg.sig.Features#FEATURE_AEAD_ENCRYPTED_DATA}.
     */
    LIBREPGP_OED // "v5"
    ;

    /**
     * Detect the type of the PGPEncryptedDataList's encrypted data packet.
     *
     * @param encDataList encrypted data list
     * @return encrypted data packet type
     * @throws PGPException if an unexpected data packet is encountered.
     */
    public static EncryptedDataPacketType of(PGPEncryptedDataList encDataList)
            throws PGPException
    {
        return of(encDataList.getEncryptedData());
    }

    /**
     * Detect the type the provided encrypted data packet.
     *
     * @param encData encrypted data packet
     * @return encrypted data packet type
     * @throws PGPException if an unexpected data packet is encountered.
     */
    public static EncryptedDataPacketType of(InputStreamPacket encData)
            throws PGPException
    {
        if (encData instanceof SymmetricEncIntegrityPacket)
        {
            SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) encData;
            if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
            {
                return SEIPDv1;
            }
            else if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_2)
            {
                return SEIPDv2;
            }
            else
            {
                throw new UnsupportedPacketVersionException("Symmetrically-Encrypted Integrity-Protected Data Packet of unknown version encountered: " + seipd.getVersion());
            }
        }
        else if (encData instanceof AEADEncDataPacket)
        {
            return LIBREPGP_OED;
        }
        else if (encData instanceof SymmetricEncDataPacket)
        {
            return SED;
        }
        else
        {
            throw new PGPException("Unexpected packet type: " + encData.getClass().getName());
        }
    }
}
