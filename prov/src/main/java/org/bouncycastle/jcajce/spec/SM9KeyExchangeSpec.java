package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameter spec for the SM9 key exchange protocol (GM/T 0044.3-2016) through
 * {@code KeyAgreement.SM9}: the two things the protocol needs that the
 * {@code KeyAgreement} API has no slot for - which role this party plays, and
 * the length of the agreed key, which is an input to the GM/T 0044.3 key
 * derivation rather than a truncation of its output.
 * <p>
 * Everything else the exchange needs comes from the key the
 * {@code KeyAgreement} is initialised with (this party's key-exchange user key
 * from
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPrivateKey#generateExchangeKeyPair(byte[])})
 * or from the peer's key supplied to {@code doPhase}: the master public key and
 * the hid ride on the user key, so this party's ephemeral value is generated
 * inside the provider under its own master key and cannot be mis-bound to
 * another.
 * <p>
 * The optional GM/T 0044.3 key-confirmation tags S_A / S_B have no channel in
 * the {@code KeyAgreement} API; a caller needing them should use the
 * lightweight {@link org.bouncycastle.crypto.agreement.SM9KeyExchange}
 * directly, as {@code KeyAgreement.SM2} callers do for SM2's tags.
 */
public class SM9KeyExchangeSpec
    implements AlgorithmParameterSpec
{
    private final boolean initiator;
    private final int keyLengthBits;

    /**
     * Base constructor, with the 128-bit key length of the GM/T 0044.5 worked
     * examples.
     *
     * @param initiator whether this party is the initiator (user A).
     */
    public SM9KeyExchangeSpec(boolean initiator)
    {
        this(initiator, 128);
    }

    /**
     * @param initiator     whether this party is the initiator (user A).
     * @param keyLengthBits the length of the agreed key in bits.
     */
    public SM9KeyExchangeSpec(boolean initiator, int keyLengthBits)
    {
        if (keyLengthBits <= 0)
        {
            throw new IllegalArgumentException("keyLengthBits must be positive");
        }
        this.initiator = initiator;
        this.keyLengthBits = keyLengthBits;
    }

    public boolean isInitiator()
    {
        return initiator;
    }

    /**
     * The agreed key length in bits - an input to the GM/T 0044.3 key derivation.
     */
    public int getKeyLengthBits()
    {
        return keyLengthBits;
    }
}
