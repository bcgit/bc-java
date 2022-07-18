package org.bouncycastle.openpgp;

/**
 * key flag values for the KeyFlags subpacket.
 */
public interface PGPKeyFlags
{
    int CAN_CERTIFY = 0x01; // This key may be used to certify other keys.

    int CAN_SIGN = 0x02; // This key may be used to sign data.

    int CAN_ENCRYPT_COMMS = 0x04; // This key may be used to encrypt communications.

    int CAN_ENCRYPT_STORAGE = 0x08; // This key may be used to encrypt storage.

    int MAYBE_SPLIT = 0x10; // The private component of this key may have been split by a secret-sharing mechanism.

    int CAN_AUTHENTICATE = 0x20; // This key maybe used for authentication.

    int MAYBE_SHARED = 0x80; // The private component of this key may be in the possession of more than one person.
}
