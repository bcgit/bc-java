package org.bouncycastle.pqc.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Pair for a value exchange algorithm where the responding party has no private key, such as NewHope.
 */
public class ExchangePair
{
    private final AsymmetricKeyParameter publicKey;
    private final byte[] shared;

    /**
     * Base constructor.
     *
     * @param publicKey The responding party's public key.
     * @param shared the calculated shared value.
     */
    public ExchangePair(AsymmetricKeyParameter publicKey, byte[] shared)
    {
        this.publicKey = publicKey;
        this.shared = Arrays.clone(shared);
    }

    /**
     * Return the responding party's public key.
     *
     * @return the public key calculated for the exchange.
     */
    public AsymmetricKeyParameter getPublicKey()
    {
        return publicKey;
    }

    /**
     * Return the shared value calculated with public key.
     *
     * @return the shared value.
     */
    public byte[] getSharedValue()
    {
        return Arrays.clone(shared);
    }
}
