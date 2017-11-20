package org.bouncycastle.jcajce.spec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec to provide MQV ephemeral keys and user keying material.
 */
public class MQVParameterSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey ephemeralPublicKey;
    private final PrivateKey ephemeralPrivateKey;
    private final PublicKey otherPartyEphemeralKey;
    private final byte[] userKeyingMaterial;

    public MQVParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
    }

    public MQVParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null);
    }

    public MQVParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, userKeyingMaterial);
    }

    public MQVParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
    {
        this(null, ephemeralPrivateKey, otherPartyEphemeralKey, userKeyingMaterial);
    }

    public MQVParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey)
    {
        this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, null);
    }

    public MQVParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey)
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
