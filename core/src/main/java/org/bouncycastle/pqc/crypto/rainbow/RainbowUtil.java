package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

/**
 * This class is needed for the conversions while encoding and decoding, as well as for
 * comparison between arrays of some dimensions
 */
class RainbowUtil
{
    /**
     * This function converts an one-dimensional array of bytes into a
     * one-dimensional array of type short
     *
     * @param in the array to be converted
     * @return out
     * one-dimensional short-array that corresponds the input
     */
    public static short[] convertArray(byte[] in)
    {
        short[] out = new short[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (short)(in[i] & GF2Field.MASK);
        }
        return out;
    }

    /**
     * This function converts an array of type short into an array of type byte
     *
     * @param in the array to be converted
     * @return out
     * the byte-array that corresponds the input
     */
    public static byte[] convertArray(short[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (byte)in[i];
        }
        return out;
    }

    /**
     * Compare two short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[] left, short[] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= left[i] == right[i];
        }
        return result;
    }

    /**
     * Compare two two-dimensional short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[][] left, short[][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= equals(left[i], right[i]);
        }
        return result;
    }

    /**
     * Compare two three-dimensional short arrays. No null checks are performed.
     *
     * @param left  the first short array
     * @param right the second short array
     * @return the result of the comparison
     */
    public static boolean equals(short[][][] left, short[][][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= equals(left[i], right[i]);
        }
        return result;
    }

    public static short[][] cloneArray(short[][] toCopy)
    {
        short[][] local = new short[toCopy.length][];
        for (int i = 0; i < toCopy.length; i++)
        {
            local[i] = Arrays.clone(toCopy[i]);
        }
        return local;
    }

    public static short[][][] cloneArray(short[][][] toCopy)
    {
        short[][][] local = new short[toCopy.length][toCopy[0].length][];
        for (int i = 0; i < toCopy.length; i++)
        {
            for (int j = 0; j < toCopy[0].length; j++)
            {
                local[i][j] = Arrays.clone(toCopy[i][j]);
            }
        }
        return local;
    }

    public static byte[] hash(Digest hashAlgo, byte[] partA, byte[] partB, byte[] result)
    {
        int digest_size = hashAlgo.getDigestSize();
        // final_hash = hash(msg) || hash(hash(msg)) || ...
        byte[] final_hash;

        // initial hash of msg
        hashAlgo.update(partA, 0, partA.length);
        hashAlgo.update(partB, 0, partB.length);

        if (result.length == digest_size)
        {
            hashAlgo.doFinal(result, 0);
            return result;
        }

        byte[] hash = new byte[digest_size];

        hashAlgo.doFinal(hash, 0);
        // check if truncation is needed
        if (result.length < digest_size)
        {
            System.arraycopy(hash, 0, result, 0, result.length);
            return result;
        }

        System.arraycopy(hash, 0, result, 0, hash.length);

        // compute expansion while needed
        int left_to_hash = result.length - digest_size;
        int index = digest_size;
        while (left_to_hash >= hash.length)
        {
            hashAlgo.update(hash, 0, hash.length);
            hashAlgo.doFinal(hash, 0);
            System.arraycopy(hash, 0, result, index, hash.length);
            left_to_hash -= hash.length;
            index += hash.length;
        }

        // check if final expansion is needed
        if (left_to_hash > 0)
        {
            hashAlgo.update(hash, 0, hash.length);
            hashAlgo.doFinal(hash, 0);
            System.arraycopy(hash, 0, result, index, left_to_hash);
        }

        return result;
    }

    public static byte[] hash(Digest hashAlgo, byte[] msg, int hash_length)
    {
        int digest_size = hashAlgo.getDigestSize();
        // final_hash = hash(msg) || hash(hash(msg)) || ...
        byte[] final_hash;

        // initial hash of msg
        hashAlgo.update(msg, 0, msg.length);
        byte[] hash = new byte[digest_size];
        hashAlgo.doFinal(hash, 0);

        // check if truncation is needed
        if (hash_length == digest_size)
        {
            return hash;
        }
        else if (hash_length < digest_size)
        {
            return Arrays.copyOf(hash, hash_length);
        }
        else
        {
            final_hash = Arrays.copyOf(hash, digest_size);
        }

        // compute expansion while needed
        int left_to_hash = hash_length - digest_size;
        while (left_to_hash >= digest_size)
        {
            hashAlgo.update(hash, 0, digest_size);
            hash = new byte[digest_size];
            hashAlgo.doFinal(hash, 0);
            final_hash = Arrays.concatenate(final_hash, hash);
            left_to_hash -= digest_size;
        }

        // check if final expansion is needed
        if (left_to_hash > 0)
        {
            hashAlgo.update(hash, 0, digest_size);
            hash = new byte[digest_size];
            hashAlgo.doFinal(hash, 0);
            int current_length = final_hash.length;
            final_hash = Arrays.copyOf(final_hash, current_length + left_to_hash);
            System.arraycopy(hash, 0, final_hash, current_length, left_to_hash);
        }

        return final_hash;
    }

    public static short[][] generate_random_2d(SecureRandom sr, int dim_row, int dim_col)
    {
        byte[] tmp = new byte[dim_row * dim_col];
        sr.nextBytes(tmp);

        short[][] matrix = new short[dim_row][dim_col];

        for (int j = 0; j < dim_col; j++)
        {
            for (int i = 0; i < dim_row; i++)
            {
                matrix[i][j] = (short)((tmp[j * dim_row + i] & GF2Field.MASK));
            }
        }

        return matrix;
    }

    public static short[][][] generate_random(SecureRandom sr, int dim_batch, int dim_row, int dim_col, boolean triangular)
    {
        int bytes_needed;
        if (triangular)
        {
            bytes_needed = dim_batch * (dim_row * (dim_row + 1) / 2);
        }
        else
        {
            bytes_needed = dim_batch * dim_row * dim_col;
        }
        byte[] tmp = new byte[bytes_needed];
        sr.nextBytes(tmp);
        int index = 0;

        short[][][] matrix = new short[dim_batch][dim_row][dim_col];

        for (int i = 0; i < dim_row; i++)
        {
            for (int j = 0; j < dim_col; j++)
            {
                for (int k = 0; k < dim_batch; k++)
                {
                    if (triangular && (i > j))
                    {
                        continue;
                    }
                    matrix[k][i][j] = (short)((tmp[index++] & GF2Field.MASK));
                }
            }
        }
        return matrix;
    }

    public static byte[] getEncoded(short[][] a)
    {
        int row = a.length;
        int col = a[0].length;

        byte[] ret = new byte[row * col];
        for (int j = 0; j < col; j++)
        {
            for (int i = 0; i < row; i++)
            {
                ret[j * row + i] = (byte)a[i][j];
            }
        }
        return ret;
    }

    public static byte[] getEncoded(short[][][] a, boolean triangular)
    {
        int dim = a.length;
        int row = a[0].length;
        int col = a[0][0].length;
        int ret_size;

        if (triangular)
        {
            ret_size = dim * (row * (row + 1) / 2);
        }
        else
        {
            ret_size = dim * row * col;
        }
        byte[] ret = new byte[ret_size];
        int cnt = 0;

        for (int i = 0; i < row; i++)
        {
            for (int j = 0; j < col; j++)
            {
                for (int k = 0; k < dim; k++)
                {
                    if (triangular && (i > j))
                    {
                        continue;
                    }
                    ret[cnt] = (byte)a[k][i][j];
                    cnt++;
                }
            }
        }
        return ret;
    }

    public static int loadEncoded(short[][] a, byte[] enc, int off)
    {
        int row = a.length;
        int col = a[0].length;

        for (int j = 0; j < col; j++)
        {
            for (int i = 0; i < row; i++)
            {
                 a[i][j] = (short)(enc[off + j * row + i] & 0xff);
            }
        }
        return row * col;
    }

    public static int loadEncoded(short[][][] a, byte[] enc, int off, boolean triangular)
    {
        int dim = a.length;
        int row = a[0].length;
        int col = a[0][0].length;

        int cnt = 0;

        for (int i = 0; i < row; i++)
        {
            for (int j = 0; j < col; j++)
            {
                for (int k = 0; k < dim; k++)
                {
                    if (triangular && (i > j))
                    {
                        continue;
                    }
                    a[k][i][j] = (short)(enc[off + cnt++] & 0xff);
                }
            }
        }
        return cnt;
    }
}
