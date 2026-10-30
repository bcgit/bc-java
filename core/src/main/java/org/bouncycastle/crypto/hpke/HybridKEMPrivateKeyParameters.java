package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Private (decapsulation) key of one of the ML-KEM / NIST curve hybrid KEMs of
 * draft-irtf-cfrg-concrete-hybrid-kems used with HPKE ({@link HPKE#kem_MLKEM768_P256},
 * {@link HPKE#kem_MLKEM1024_P384}). The key is a 32-byte seed, which is also its
 * serialized form; the ML-KEM and curve components are expanded from it.
 */
public class HybridKEMPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    private final short kemId;
    private final byte[] seed;
    private final MLKEMPrivateKeyParameters pqKey;
    private final ECPrivateKeyParameters tKey;
    private final HybridKEMPublicKeyParameters publicKey;

    HybridKEMPrivateKeyParameters(short kemId, byte[] seed, MLKEMPrivateKeyParameters pqKey, ECPrivateKeyParameters tKey,
        HybridKEMPublicKeyParameters publicKey)
    {
        super(true);

        this.kemId = kemId;
        this.seed = Arrays.clone(seed);
        this.pqKey = pqKey;
        this.tKey = tKey;
        this.publicKey = publicKey;
    }

    public short getKemId()
    {
        return kemId;
    }

    /**
     * Return the 32-byte seed the key pair is derived from, which is the key's serialized form.
     */
    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public byte[] getEncoded()
    {
        return getSeed();
    }

    public HybridKEMPublicKeyParameters getPublicKeyParameters()
    {
        return publicKey;
    }

    MLKEMPrivateKeyParameters getPQKey()
    {
        return pqKey;
    }

    ECPrivateKeyParameters getTKey()
    {
        return tKey;
    }
}
