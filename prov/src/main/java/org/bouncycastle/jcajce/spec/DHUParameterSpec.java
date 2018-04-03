package org.bouncycastle.jcajce.spec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec to provide Diffie-Hellman Unified model keys and user keying material.
 */
public class DHUParameterSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey ephemeralPublicKey;
    private final PrivateKey ephemeralPrivateKey;
    private final PublicKey otherPartyEphemeralKey;
    private final byte[] userKeyingMaterial;

    /**
     * Base constructor for a Diffie-Hellman unified model.
     *
     * @param ephemeralPublicKey our ephemeral public key.
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the ephemeral public key sent by the other party.
     * @param userKeyingMaterial key generation material to mix with the calculated secret.
     */
    public DHUParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        if (ephemeralPrivateKey == null)
        {
            throw new IllegalArgumentException("ephemeral private key cannot be null");
        }
        if (otherPartyEphemeralKey == null)
        {
            throw new IllegalArgumentException("other party ephemeral key cannot be null");
        }
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
    }

    /**
     * Base constructor for a Diffie-Hellman unified model without user keying material.
     *
     * @param ephemeralPublicKey our ephemeral public key.
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the ephemeral public key sent by the other party.
     */
    public DHUParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    /**
     * Base constructor for a Diffie-Hellman unified model using a key pair.
     *
     * @param ephemeralKeyPair our ephemeral public and private key.
     * @param otherPartyEphemeralKey the ephemeral public key sent by the other party.
     * @param userKeyingMaterial key generation material to mix with the calculated secret.
     */
    public DHUParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, userKeyingMaterial);
    }

    /**
     * Base constructor for a Diffie-Hellman unified model - calculation of our ephemeral public key
     * is required.
     *
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the ephemeral public key sent by the other party.
     * @param userKeyingMaterial key generation material to mix with the calculated secret.
     */
    public DHUParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, userKeyingMaterial);
    }

    /**
     * Base constructor for a Diffie-Hellman unified model using a key pair without user keying material.
     *
     * @param ephemeralKeyPair our ephemeral public and private key.
     * @param otherPartyEphemeralKey the ephemeral public key sent by the other party.
     */
    public DHUParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, null);
    }

    /**
     * Base constructor for a Diffie-Hellman unified model - calculation of our ephemeral public key
     * is required and no user keying material is provided.
     *
     * @param ephemeralPrivateKey our ephemeral private key.
     * @param otherPartyEphemeralKey the ephemeral public key sent by the other party.
     */
    public DHUParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    /**
     * Return our ephemeral private key.
     *
     * @return our ephemeral private key.
     */
    public PrivateKey getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    /**
     * Return our ephemeral public key, null if it was not provided.
     *
     * @return our ephemeral public key, can be null.
     */
    public PublicKey getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }

    /**
     * Return the ephemeral other party public key.
     *
     * @return the ephemeral other party public key.
     */
    public PublicKey getOtherPartyEphemeralKey()
    {
        return otherPartyEphemeralKey;
    }

    /**
     * Return a copy of the user keying material, null if none is available.
     *
     * @return a copy of the user keying material, can be null.
     */
    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }
}
