package org.bouncycastle.crypto.params;

/**
 * A master key capable of the KGC user-key extraction for an identity-based
 * encryption-family scheme: deriving a user's private key from the user's
 * identity and the private-key generation function identifier hid the KGC
 * chose (GM/T 0044.3/0044.4-2016 for SM9, where one encryption master key
 * serves key exchange, KEM and public-key encryption).
 * <p>
 * The hid is what separates the functions a KGC offers. <b>Usage warning:</b> a key
 * derived here should be used for the KEM or for public-key encryption, but not for both;
 * a KGC offering both functions publishes a separate hid for each, as it does for the key
 * exchange.
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
     * @param hid the private-key generation function identifier the KGC chose for
     *            the encryption function, {@link SM9EncMasterPrivateKeyParameters#HID}.
     *            {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE} names the key
     *            exchange's own function and is refused here - a key derived under it
     *            is that identity's exchange key, which the two usages are kept apart
     *            to stop a KEM or decryption key from also being. A KGC offering both
     *            the KEM and public-key encryption publishes a further value of its own
     *            for one of them, so that no identity's key serves both.
     * @return the user's private key.
     */
    SM9EncPrivateKeyParameters generateUserKey(byte[] identity, byte hid);
}
