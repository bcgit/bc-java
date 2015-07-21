package org.bouncycastle.openpgp;

/**
 * key flag values for the KeyFlags subpacket.
 */
public interface PGPKeyFlags
{
    public static final int CAN_CERTIFY = 0x01; // This key may be used to certify other keys.

    public static final int CAN_SIGN = 0x02; // This key may be used to sign data.

    public static final int CAN_ENCRYPT_COMMS = 0x04; // This key may be used to encrypt communications.

    public static final int CAN_ENCRYPT_STORAGE = 0x08; // This key may be used to encrypt storage.

    public static final int MAYBE_SPLIT = 0x10; // The private component of this key may have been split by a secret-sharing mechanism.

    public static final int CAN_AUTHENTICATE = 0x20; // This key maybe used for authentication.

    public static final int MAYBE_SHARED = 0x80; // The private component of this key may be in the possession of more than one person.
}
