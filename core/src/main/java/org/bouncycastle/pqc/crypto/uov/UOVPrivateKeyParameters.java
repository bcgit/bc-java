package org.bouncycastle.pqc.crypto.uov;

import org.bouncycastle.util.Arrays;

public class UOVPrivateKeyParameters
    extends UOVKeyParameters
{
    private final byte[] encoded;
    private final byte[] seed;

    public UOVPrivateKeyParameters(UOVParameters params, byte[] encoded)
    {
        this(params, encoded, null);
    }

    /**
     * Construct from the full classic encoding (sk_seed || O || P1 || S).
     *
     * @param params the parameter set.
     * @param encoded the full secret-key encoding.
     * @param seed optional 32-byte seed when the caller has it separately;
     *             if non-null, must match the first 32 bytes of {@code encoded}.
     */
    public UOVPrivateKeyParameters(UOVParameters params, byte[] encoded, byte[] seed)
    {
        super(true, params);
        if (encoded == null)
        {
            throw new NullPointerException("encoded cannot be null");
        }
        if (encoded.length != params.getSecretKeyBytes())
        {
            throw new IllegalArgumentException("secret key encoding wrong length for " + params.getName());
        }
        this.encoded = Arrays.clone(encoded);
        if (seed != null)
        {
            if (seed.length != UOVParameters.SK_SEED_BYTES)
            {
                throw new IllegalArgumentException("seed must be " + UOVParameters.SK_SEED_BYTES + " bytes");
            }
            byte[] embedded = new byte[UOVParameters.SK_SEED_BYTES];
            System.arraycopy(encoded, 0, embedded, 0, UOVParameters.SK_SEED_BYTES);
            if (!Arrays.constantTimeAreEqual(seed, embedded))
            {
                throw new IllegalArgumentException("seed does not match encoded sk_seed prefix");
            }
            this.seed = Arrays.clone(seed);
        }
        else
        {
            this.seed = Arrays.copyOfRange(encoded, 0, UOVParameters.SK_SEED_BYTES);
        }
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    /**
     * Package-private read-only view of the encoded key. Returns the
     * internal byte[] without cloning so the engine can avoid allocating
     * multi-MB defensive copies per sign call. Callers MUST treat the
     * returned array as read-only; never mutate, never expose.
     */
    byte[] borrowEncoded()
    {
        return encoded;
    }
}
