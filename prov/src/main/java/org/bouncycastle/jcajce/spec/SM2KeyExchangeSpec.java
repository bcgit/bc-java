package org.bouncycastle.jcajce.spec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

public class SM2KeyExchangeSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey ephemeralPublicKey;
    private final PrivateKey ephemeralPrivateKey;
    private final PublicKey otherPartyEphemeralKey;
    private final byte[] id;
    private final byte[] otherPartyId;
    private final boolean initiator;

    public SM2KeyExchangeSpec(boolean initiator, PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey,
                              PublicKey otherPartyEphemeralKey, byte[] id, byte[] otherPartyId)
    {
        this.initiator = initiator;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.otherPartyEphemeralKey = otherPartyEphemeralKey;
        this.id = Arrays.clone(id);
        this.otherPartyId = Arrays.clone(otherPartyId);
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

    public byte[] getId()
    {
        return Arrays.clone(id);
    }

    public byte[] getOtherPartyId()
    {
        return Arrays.clone(otherPartyId);
    }

    public boolean isInitiator()
    {
        return initiator;
    }
}

