package org.bouncycastle.crypto.params;

/**
 * A master key capable of the KGC user-key extraction for an identity-based
 * encryption-family scheme: deriving a user's private key from the user's
 * identity and the private-key generation function identifier hid the KGC
 * chose (GM/T 0044.3/0044.4-2016 for SM9, where one encryption master key
 * serves key exchange, KEM and public-key encryption, distinguished by hid).
 *
 * @see SM9SigUserKeyParametersGenerator
 */
public interface SM9EncUserKeyParametersGenerator
{
    /**
     * Derive the private key of the user identified by {@code identity} under the
     * given hid, a deterministic KGC operation - the same master key, identity
     * and hid always yield the same user key.
     *
     * @param identity  the user's identity.
     * @param hid the private-key generation function identifier the KGC chose,
     *            {@link SM9EncMasterPrivateKeyParameters#HID} or
     *            {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE}.
     * @return the user's private key.
     */
    SM9EncPrivateKeyParameters generateUserKey(byte[] identity, byte hid);
}
