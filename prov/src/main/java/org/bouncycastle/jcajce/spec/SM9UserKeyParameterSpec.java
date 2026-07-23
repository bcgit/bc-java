package org.bouncycastle.jcajce.spec;

import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameters for generating an SM9 user key pair: the KGC's encryption master private
 * key together with the user's identity. Initialising a {@code KeyPairGenerator.SM9-ENC}
 * with this spec makes {@code generateKeyPair()} return the identified user's key pair -
 * the public key to encapsulate to (the master public key bound to the identity) and the
 * private key that decapsulates.
 * <p>
 * In GM/T 0044 terms this is the KGC's key-extraction operation; the JCA expresses it as
 * key-pair generation parameterised by identity, just as EC key generation is parameterised
 * by curve. The derivation is deterministic: the same master key and identity always yield
 * the same key pair.
 */
public class SM9UserKeyParameterSpec
    implements AlgorithmParameterSpec
{
    private final PrivateKey masterPrivateKey;
    private final byte[] identity;

    /**
     * @param masterPrivateKey the KGC's encryption master private key (an SM9-ENC private key).
     * @param identity the identity of the user the key pair is generated for.
     */
    public SM9UserKeyParameterSpec(PrivateKey masterPrivateKey, byte[] identity)
    {
        if (masterPrivateKey == null)
        {
            throw new NullPointerException("masterPrivateKey cannot be null");
        }
        if (identity == null)
        {
            throw new NullPointerException("identity cannot be null");
        }
        this.masterPrivateKey = masterPrivateKey;
        this.identity = Arrays.clone(identity);
    }

    public PrivateKey getMasterPrivateKey()
    {
        return masterPrivateKey;
    }

    public byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }
}
