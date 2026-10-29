package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Derivation parameters for the NIST SP 800-108 Rev. 1 key-based key derivation functions
 * ({@code KDF.getInstance("KBKDF-COUNTER-HMACSHA256")}, "KBKDF-FEEDBACK-HMACSHA256",
 * "KBKDF-PIPELINE-HMACSHA256", ...): the input key K_IN, the fixed input data, the output length, the
 * counter length and, for feedback mode, the IV.
 * <p>
 * The {@link #KBKDFParameterSpec(byte[], byte[], byte[], int)} constructor builds the fixed input data in
 * the layout the standard's Section 4 suggests, Label || 0x00 || Context || [L]_32 with L the output length
 * in bits, and uses a 32-bit counter. The counter precedes the fixed input data in counter mode, and
 * follows the chaining value in feedback and double-pipeline mode; a counter length of 0 omits the
 * counter in those two modes, as the standard allows.
 */
public class KBKDFParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] keyIn;
    private final byte[] fixedInputData;
    private final int outputLength;
    private final int counterBits;
    private final byte[] iv;

    /**
     * The standard layout: Label || 0x00 || Context || [L]_32, with a 32-bit counter.
     *
     * @param keyIn        the input key K_IN.
     * @param label        the label, may be null.
     * @param context      the context, may be null.
     * @param outputLength the number of bytes to derive.
     */
    public KBKDFParameterSpec(byte[] keyIn, byte[] label, byte[] context, int outputLength)
    {
        this(keyIn, standardFixedInput(label, context, outputLength), outputLength, 32, null);
    }

    /**
     * Caller-supplied fixed input data.
     *
     * @param keyIn          the input key K_IN.
     * @param fixedInputData the fixed input data, may be null.
     * @param outputLength   the number of bytes to derive.
     * @param counterBits    the counter length in bits: 8, 16, 24 or 32, or 0 for no counter (feedback and
     *                       double-pipeline mode only).
     */
    public KBKDFParameterSpec(byte[] keyIn, byte[] fixedInputData, int outputLength, int counterBits)
    {
        this(keyIn, fixedInputData, outputLength, counterBits, null);
    }

    private KBKDFParameterSpec(byte[] keyIn, byte[] fixedInputData, int outputLength, int counterBits, byte[] iv)
    {
        if (keyIn == null)
        {
            throw new IllegalArgumentException("keyIn should not be null");
        }
        if (outputLength <= 0)
        {
            throw new IllegalArgumentException("outputLength must be positive");
        }
        if (counterBits != 0 && counterBits != 8 && counterBits != 16 && counterBits != 24 && counterBits != 32)
        {
            throw new IllegalArgumentException("counterBits must be 0, 8, 16, 24 or 32");
        }
        this.keyIn = Arrays.clone(keyIn);
        this.fixedInputData = (fixedInputData == null) ? new byte[0] : Arrays.clone(fixedInputData);
        this.outputLength = outputLength;
        this.counterBits = counterBits;
        this.iv = Arrays.clone(iv);
    }

    private static byte[] standardFixedInput(byte[] label, byte[] context, int outputLength)
    {
        if (label == null)
        {
            label = new byte[0];
        }
        if (context == null)
        {
            context = new byte[0];
        }

        return Arrays.concatenate(label, new byte[1], context, Pack.intToBigEndian(outputLength * 8));
    }

    /**
     * Return a copy of this spec with the IV feedback mode chains from.
     *
     * @param iv the IV, may be null for an empty IV.
     * @return a new spec carrying the IV.
     */
    public KBKDFParameterSpec withIV(byte[] iv)
    {
        return new KBKDFParameterSpec(keyIn, fixedInputData, outputLength, counterBits, iv);
    }

    public byte[] getKeyIn()
    {
        return Arrays.clone(keyIn);
    }

    public byte[] getFixedInputData()
    {
        return Arrays.clone(fixedInputData);
    }

    public int getOutputLength()
    {
        return outputLength;
    }

    /**
     * @return the counter length in bits, 0 for no counter.
     */
    public int getCounterBits()
    {
        return counterBits;
    }

    /**
     * @return the feedback mode IV, or null if none was given.
     */
    public byte[] getIV()
    {
        return Arrays.clone(iv);
    }
}
