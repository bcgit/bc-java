package org.bouncycastle.jcajce.spec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec to provide Diffie-Hellman ephemeral keys and user keying material.
 */
public class DHEParameterSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey ephemeralPublicKey;
    private final PrivateKey ephemeralPrivateKey;
    private final PublicKey otherPartyEphemeralKey;
    private final byte[] userKeyingMaterial;

    public DHEParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
    }

    public DHEParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    public DHEParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, userKeyingMaterial);
    }

    public DHEParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, userKeyingMaterial);
    }

    public DHEParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, null);
    }

    public DHEParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    public PrivateKey getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public PublicKey getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }

    public PublicKey getOtherPartyEphemeralKey()
    {
        return otherPartyEphemeralKey;
    }

    public byte[] getUserKeyingMaterial()
    {
        return Arrays.clone(userKeyingMaterial);
    }
}
