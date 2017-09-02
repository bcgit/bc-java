package org.bouncycastle.bcpg;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Parameter specifier for the PGP string-to-key password based key derivation function.
 * <p>
 * In iterated mode, S2K takes a single byte iteration count specifier, which is converted to an
 * actual iteration count using a formula that grows the iteration count exponentially as the byte
 * value increases.
 * </p><p>
 * e.g. <code>0x01</code> == 1088 iterations, and <code>0xFF</code> == 65,011,712 iterations.
 * </p>
 */
public class S2K
    extends BCPGObject
{
    private static final int EXPBIAS = 6;

    /** Simple key generation. A single non-salted iteration of a hash function */
    public static final int SIMPLE = 0;
    /** Salted key generation. A single iteration of a hash function with a (unique) salt */
    public static final int SALTED = 1;
    /** Salted and iterated key generation. Multiple iterations of a hash function, with a salt */
    public static final int SALTED_AND_ITERATED = 3;

    public static final int GNU_DUMMY_S2K = 101;

    public static final int GNU_PROTECTION_MODE_NO_PRIVATE_KEY = 1;
    public static final int GNU_PROTECTION_MODE_DIVERT_TO_CARD = 2;

    int       type;
    int       algorithm;
    byte[]    iv;
    int       itCount = -1;
    int       protectionMode = -1;

    S2K(
        InputStream    in)
        throws IOException
    {
        DataInputStream    dIn = new DataInputStream(in);

        type = dIn.read();
        algorithm = dIn.read();

        //
        // if this happens we have a dummy-S2K packet.
        //
        if (type != GNU_DUMMY_S2K)
        {
            if (type != 0)
            {
                iv = new byte[8];
                dIn.readFully(iv, 0, iv.length);

                if (type == 3)
                {
                    itCount = dIn.read();
                }
            }
        }
        else
        {
            dIn.read(); // G
            dIn.read(); // N
            dIn.read(); // U
            protectionMode = dIn.read(); // protection mode
        }
    }

    /**
     * Constructs a specifier for a {@link #SIMPLE simple} S2K generation.
     *
     * @param algorithm the {@link HashAlgorithmTags digest algorithm} to use.
     */
    public S2K(
        int        algorithm)
    {
        this.type = 0;
        this.algorithm = algorithm;
    }

    /**
     * Constructs a specifier for a {@link #SALTED salted} S2K generation.
     *
     * @param algorithm the {@link HashAlgorithmTags digest algorithm} to use.
     * @param iv the salt to apply to input to the key generation.
     */
    public S2K(
        int        algorithm,
        byte[]    iv)
    {
        this.type = 1;
        this.algorithm = algorithm;
        this.iv = iv;
    }

    /**
     * Constructs a specifier for a {@link #SALTED_AND_ITERATED salted and iterated} S2K generation.
     *
     * @param algorithm the {@link HashAlgorithmTags digest algorithm} to iterate.
     * @param iv the salt to apply to input to the key generation.
     * @param itCount the single byte iteration count specifier.
     */
    public S2K(
        int       algorithm,
        byte[]    iv,
        int       itCount)
    {
        this.type = 3;
        this.algorithm = algorithm;
        this.iv = iv;
        this.itCount = itCount;
    }

    /**
     * Gets the {@link HashAlgorithmTags digest algorithm} specified.
     */
    public int getType()
    {
        return type;
    }

    /**
     * Gets the {@link HashAlgorithmTags hash algorithm} for this S2K.
     */
    public int getHashAlgorithm()
    {
        return algorithm;
    }

    /**
     * Gets the iv/salt to use for the key generation.
     */
    public byte[] getIV()
    {
        return iv;
    }

    /**
     * Gets the actual (expanded) iteration count.
     */
    public long getIterationCount()
    {
        return (16 + (itCount & 15)) << ((itCount >> 4) + EXPBIAS);
    }

    /**
     * Gets the protection mode - only if GNU_DUMMY_S2K
     */
    public int getProtectionMode()
    {
        return protectionMode;
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.write(type);
        out.write(algorithm);

        if (type != GNU_DUMMY_S2K)
        {
            if (type != 0)
            {
                out.write(iv);
            }

            if (type == 3)
            {
                out.write(itCount);
            }
        }
        else
        {
            out.write('G');
            out.write('N');
            out.write('U');
            out.write(protectionMode);
        }
    }
}
