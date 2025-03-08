package org.bouncycastle.openpgp.api;

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
}
