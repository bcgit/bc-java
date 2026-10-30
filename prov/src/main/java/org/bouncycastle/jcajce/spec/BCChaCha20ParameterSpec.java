package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameters for the RFC 8439 (formerly RFC 7539) form of the ChaCha20 stream cipher - "ChaCha7539", also
 * registered as "ChaCha20", in the BC provider: a 12 byte nonce and the initial value of the 32 bit block
 * counter.
 * <p>
 * This is the BC equivalent of {@code javax.crypto.spec.ChaCha20ParameterSpec}, which only exists from Java 11,
 * and carries the same values with the same meaning; the BC provider accepts either. Starting the cipher at a
 * given block is what, for example, the record number protection of DTLS 1.3 (RFC 9147 sec. 4.2.3) and the
 * header protection of QUIC (RFC 9001 sec. 5.4.4) require.
 * </p>
 * <p>
 * The counter is an unsigned 32 bit value carried in an {@code int}, so a negative counter addresses one of the
 * blocks from 2^31 to 2^32 - 1. The cipher returns to this block, not block 0, after each {@code doFinal}.
 * </p>
 * <p>
 * An {@code AlgorithmParameters} object has no way of carrying the counter, so a cipher initialised with a
 * non-zero counter returns {@code null} from {@code getParameters()}, as the JDK's ChaCha20 cipher does, rather
 * than parameters that would recreate the wrong key stream.
 * </p>
 */
public class BCChaCha20ParameterSpec
    implements AlgorithmParameterSpec
{
    private static final int NONCE_LENGTH = 12;

    private final byte[] nonce;
    private final int counter;

    /**
     * Base constructor.
     *
     * @param nonce   the 12 byte nonce.
     * @param counter the initial block counter, an unsigned 32 bit value.
     * @throws NullPointerException     if nonce is null.
     * @throws IllegalArgumentException if nonce is not 12 bytes long.
     */
    public BCChaCha20ParameterSpec(byte[] nonce, int counter)
    {
        if (nonce == null)
        {
            throw new NullPointerException("nonce cannot be null");
        }
        if (nonce.length != NONCE_LENGTH)
        {
            throw new IllegalArgumentException("nonce must be " + NONCE_LENGTH + " bytes long");
        }

        this.nonce = Arrays.clone(nonce);
        this.counter = counter;
    }

    /**
     * Return the nonce.
     *
     * @return a copy of the 12 byte nonce.
     */
    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    /**
     * Return the initial block counter.
     *
     * @return the initial block counter, an unsigned 32 bit value.
     */
    public int getCounter()
    {
        return counter;
    }
}
