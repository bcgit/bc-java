package org.bouncycastle.jcajce.spec;

import org.bouncycastle.util.Arrays;

/**
 * This class extends {@link UserKeyingMaterialSpec} to store additional information required
 * for HKDF in OpenPGP encryption, as outlined in sections 5.1.6 and 5.1.7 of
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/13/">draft-ietf-openpgp-crypto-refresh-13</a>.
 * <p>
 * The class is designed to hold the concatenated byte arrays of the ephemeral public keys
 * and the shared secret in the {@code prepend} field, and the user keying material (info parameter)
 * in the {@code userKeyingMaterial} field.
 */
public class UserKeyingMaterialSpecWithPrepend
    extends UserKeyingMaterialSpec
{
    private final byte[] prepend;

    /**
     * Constructs a new UserKeyingMaterialSpecWithPrepend object with the specified prepend bytes
     * and user keying material.
     *
     * @param prepend            The bytes to prepend before deriving the key, which should include:
     *                           - 32/56 octets of the ephemeral X25519 or X448 public key
     *                           - 32/56 octets of the recipient public key material
     *                           - 32/56 octets of the shared secret
     * @param userKeyingMaterial The user keying material (info parameter) used for key derivation.
     */
    public UserKeyingMaterialSpecWithPrepend(byte[] prepend, byte[] userKeyingMaterial)
    {
        super(userKeyingMaterial);
        this.prepend = Arrays.clone(prepend);
    }


    /**
     * Constructs a new UserKeyingMaterialSpecWithPrepend object with the specified prepend bytes,
     * user keying material, and salt.
     *
     * @param prepend            The bytes to prepend before deriving the key, which should include:
     *                           - 32/56 octets of the ephemeral X25519 or X448 public key
     *                           - 32/56 octets of the recipient public key material
     *                           - 32/56 octets of the shared secret
     * @param userKeyingMaterial The user keying material (info parameter) used for key derivation.
     * @param salt               The salt value used in key derivation (can be {@code null}).
     */
    public UserKeyingMaterialSpecWithPrepend(byte[] prepend, byte[] userKeyingMaterial, byte[] salt)
    {
        super(userKeyingMaterial, salt);
        this.prepend = Arrays.clone(prepend);
    }

    /**
     * Get the bytes that are prepended before deriving the key.
     *
     * @return The prepend bytes.
     */
    public byte[] getPrepend()
    {
        return Arrays.clone(prepend);
    }
}
