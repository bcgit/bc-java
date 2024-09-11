package org.bouncycastle.bcpg;

/**
 * Basic PGP packet tag types.
 */
public interface PacketTags
{
    int RESERVED = 0;                //  Reserved - a packet tag must not have this value

    /**
     * Public-Key (Persistent-Key) Encrypted Session-Key Packet.
     * Packet class: {@link PublicKeyEncSessionPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPPublicKeyEncryptedData}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-encrypted-sessio">
     * Public-Key Encrypted Session Key Packet</a>
     */
    int PUBLIC_KEY_ENC_SESSION = 1;    // Public-Key Encrypted Session Key Packet

    /**
     * Signature Packet.
     * Packet class: {@link SignaturePacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPSignature}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-packet-type-id-2">
     * Signature Packet</a>
     */
    int SIGNATURE = 2;                 // Signature Packet

    /**
     * Symmetric Key (String-to-Key) Encrypted Session-Key Packet.
     * Packet class: {@link SymmetricKeyEncSessionPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPSymmetricKeyEncryptedData}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetric-key-encrypted-ses">
     * Symmetric-Key Encrypted Session-Key Packet</a>
     */
    int SYMMETRIC_KEY_ENC_SESSION = 3; // Symmetric-Key Encrypted Session Key Packet

    /**
     * One-Pass-Signature Packet.
     * Packet class: {@link OnePassSignaturePacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPOnePassSignature},
     * {@link org.bouncycastle.openpgp.PGPOnePassSignatureList}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-one-pass-signature-packet-t">
     * One-Pass-Signature Packet</a>
     */
    int ONE_PASS_SIGNATURE = 4;       // One-Pass Signature Packet

    /**
     * (Primary) Secret-Key Packet.
     * Packet class: {@link SecretKeyPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPSecretKey}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-type-id-5">
     * Secret-Key Packet</a>
     */
    int SECRET_KEY = 5;                // Secret Key Packet

    /**
     * (Primary) Public-Key Packet.
     * Packet class: {@link PublicKeyPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPPublicKey}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-packet-type-id-6">
     * Public-Key Packet</a>
     */
    int PUBLIC_KEY = 6;               // Public Key Packet

    /**
     * Secret-Subkey Packet.
     * Packet class: {@link SecretSubkeyPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPSecretKey}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-subkey-packet-type-i">
     * Secret-Subkey Packet</a>
     */
    int SECRET_SUBKEY = 7;             // Secret Subkey Packet

    /**
     * Compressed-Data Packet.
     * Packet class: {@link CompressedDataPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPCompressedData}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-compressed-data-packet-type">
     * Compressed Data Packet</a>
     */
    int COMPRESSED_DATA = 8;           // Compressed Data Packet

    /**
     * Symmetrically Encrypted Data Packet.
     * Packet class: {@link SymmetricEncDataPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPSymmetricKeyEncryptedData}
     * Note: This encrypted data packet in favor of {@link #SYM_ENC_INTEGRITY_PRO}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetrically-encrypted-dat">
     * Symmetrically Encrypted Data Packet</a>
     */
    int SYMMETRIC_KEY_ENC = 9;         // Symmetrically Encrypted Data Packet

    /**
     * Marker Packet.
     * Packet class: {@link MarkerPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPMarker}
     * This packet is deprecated and MUST be ignored.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-marker-packet-type-id-10">
     * Marker Packet</a>
     */
    int MARKER = 10;                   // Marker Packet

    /**
     * Literal Data Packet.
     * Packet class: {@link LiteralDataPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPLiteralData}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-literal-data-packet-type-id">
     * Literal Data Packet</a>
     */
    int LITERAL_DATA = 11;             // Literal Data Packet

    /**
     * Trust Packet.
     * Packet class: {@link TrustPacket}
     * This class has no dedicated business logic implementation.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-packet-type-id-12">
     * Trust Packet</a>
     */
    int TRUST = 12;                    // Trust Packet

    /**
     * User ID Packet.
     * Packet class: {@link UserIDPacket}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-user-id-packet-type-id-13">
     * User ID Packet</a>
     */
    int USER_ID = 13;                  // User ID Packet

    /**
     * Public-Subkey Packet.
     * Packet class: {@link PublicSubkeyPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPPublicKey}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-subkey-packet-type-i">
     * Public-Subkey Packet</a>
     */
    int PUBLIC_SUBKEY = 14;            // Public Subkey Packet

    /**
     * User Attribute Packet.
     * Packet class: {@link UserAttributePacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-user-attribute-packet-type-">
     * User Attribute Packet</a>
     */
    int USER_ATTRIBUTE = 17;           // User attribute

    /**
     * Symmetrically Encrypted, Integrity-Protected Data Packet.
     * Packet class: {@link SymmetricEncIntegrityPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPSymmetricKeyEncryptedData}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetrically-encrypted-int">
     * Symmetrically Encrypted Integrity Protected Data Packet</a>
     */
    int SYM_ENC_INTEGRITY_PRO = 18;    // Symmetric encrypted, integrity protected

    /**
     * Modification Detection Code Packet.
     * This is no longer a stand-alone packet and has been integrated into the {@link #SYM_ENC_INTEGRITY_PRO}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-terminology-changes">
     * Terminology Changes</a>
     */
    int MOD_DETECTION_CODE = 19;       // Modification detection code

    /**
     * OCB Encrypted Data Packet (LibrePGP only).
     * This packet is not used by the official OpenPGP standard.
     * Packet class: {@link AEADEncDataPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPEncryptedData}
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-ocb-encrypted-data-packet-t">
     * OCB Encrypted Data Packet</a>
     */
    int AEAD_ENC_DATA = 20;            // AEAD Encrypted Data (seems deprecated)

    /**
     * Padding Packet.
     * Packet class: {@link PaddingPacket}
     * Business logic: {@link org.bouncycastle.openpgp.PGPPadding}
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-padding-packet-type-id-21">
     * Padding Packet</a>
     */
    int PADDING = 21;                  // Padding Packet

    int EXPERIMENTAL_1 = 60;           // Private or Experimental Values
    int EXPERIMENTAL_2 = 61;
    int EXPERIMENTAL_3 = 62;
    int EXPERIMENTAL_4 = 63;
}
