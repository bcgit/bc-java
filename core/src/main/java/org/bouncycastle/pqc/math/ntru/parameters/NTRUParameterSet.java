package org.bouncycastle.pqc.math.ntru.parameters;

import org.bouncycastle.pqc.math.ntru.Polynomial;

/**
 * Abstract class for all NTRU parameter sets.
 *
 * @see NTRUHPSParameterSet
 * @see NTRUHRSSParameterSet
 * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification document</a>
 */
public abstract class NTRUParameterSet
{
    private final int n;
    private final int logQ;

    private final int seedBytes;
    private final int prfKeyBytes;
    private final int sharedKeyBytes;

    public NTRUParameterSet(int n, int logQ, int seedBytes, int prfKeyBytes, int sharedKeyBytes)
    {
        this.n = n;
        this.logQ = logQ;
        this.seedBytes = seedBytes;
        this.prfKeyBytes = prfKeyBytes;
        this.sharedKeyBytes = sharedKeyBytes;
    }

    /**
     * Creates a polynomial based on this parameter set.
     *
     * @return an instance of {@link Polynomial}
     */
    public abstract Polynomial createPolynomial();

    /**
     * n
     *
     * @return n is a prime and both 2 and 3 are of order n − 1 in (Z/n)×
     */
    public int n()
    {
        return n;
    }

    /**
     * logq
     *
     * @return log2(q)
     */
    public int logQ()
    {
        return logQ;
    }

    /**
     * q
     *
     * @return q is a power of two
     */
    public int q()
    {
        return 1 << logQ;
    }

    /**
     * The number of random bytes consumed by keygen.
     *
     * @return {@code key_seed_bits/8}
     */
    public int seedBytes()
    {
        return seedBytes;
    }

    /**
     * The number of bytes used to key the implicit rejection mechanism.
     *
     * @return {@code prf_key_bits/8}
     */
    public int prfKeyBytes()
    {
        return prfKeyBytes;
    }

    /**
     * @return {@code kem_shared_key_bits/8}
     */
    public int sharedKeyBytes()
    {
        return sharedKeyBytes;
    }

    /**
     * @return {@code sample_iid_bits/8}
     */
    public int sampleIidBytes()
    {
        return n - 1;
    }

    /**
     * @return {@code sample_xed_type_bits}
     */
    public int sampleFixedTypeBytes()
    {
        return (30 * (n - 1) + 7) / 8;
    }

    /**
     * @return {@code sample_key_bits/8}
     */
    public abstract int sampleFgBytes();

    /**
     * @return {@code sample_plaintext_bits/8}
     */
    public abstract int sampleRmBytes();

    public int packDegree()
    {
        return n - 1;
    }

    /**
     * @return {@code packed_s3_bytes}
     */
    public int packTrinaryBytes()
    {
        return (packDegree() + 4) / 5;
    }

    /**
     * The number of bytes in a plaintext for the DPKE.
     *
     * @return {@code dpke_plaintext_bytes}
     */
    public int owcpaMsgBytes()
    {
        return 2 * packTrinaryBytes();
    }

    /**
     * The number of bytes in a public key for the DPKE.
     *
     * @return {@code dpke_public_key_bytes}
     */
    public int owcpaPublicKeyBytes()
    {
        return (logQ * packDegree() + 7) / 8;
    }

    /**
     * The number of bytes in a private key for the DPKE.
     *
     * @return {@code dpke_private_key_bytes}
     */
    public int owcpaSecretKeyBytes()
    {
        return 2 * packTrinaryBytes() + owcpaPublicKeyBytes();
    }

    /**
     * The number of bytes in a ciphertext for the DPKE.
     *
     * @return {@code dpke_ciphertext_bytes}
     */
    public int owcpaBytes()
    {
        return (logQ * packDegree() + 7) / 8;
    }

    /**
     * The number of bytes in a public key for the KEM.
     *
     * @return {@code kem_public_key_bytes}
     */
    public int ntruPublicKeyBytes()
    {
        return owcpaPublicKeyBytes();
    }

    /**
     * The number of bytes in a private key for the KEM.
     *
     * @return {@code kem_private_key_bytes}
     */
    public int ntruSecretKeyBytes()
    {
        return owcpaSecretKeyBytes() + prfKeyBytes;
    }

    /**
     * The number of bytes in a ciphertext for the KEM.
     *
     * @return {@code kem_ciphertext_bytes}
     */
    public int ntruCiphertextBytes()
    {
        return owcpaBytes();
    }
}
