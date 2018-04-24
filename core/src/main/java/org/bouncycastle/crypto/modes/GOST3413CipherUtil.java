package org.bouncycastle.crypto.modes;

import org.bouncycastle.util.Arrays;

/**
 * Some methods for GOST 3412 cipher algorithm
 */
class GOST3413CipherUtil
{
    /**
     * copy first <b>size</b> elements from <b>from</b>
     *
     * @param from source array
     * @param size size of new array
     * @return
     */
    public static byte[] MSB(byte[] from, int size)
    {
        return Arrays.copyOf(from, size);
    }


    /**
     * copy last <b>size</b> elements from <b>from</b>
     *
     * @param from source array
     * @param size size of new array
     * @return
     */
    public static byte[] LSB(byte[] from, int size)
    {
        byte[] result = new byte[size];
        System.arraycopy(from, from.length - size, result, 0, size);
        return result;
    }


    /**
     * componentwise addition modulo 2 (XOR)
     *
     * @param in    clear text
     * @param gamma gamma parameter
     * @return
     */
    public static byte[] sum(byte[] in, byte[] gamma)
    {

        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++)
        {
            out[i] = (byte)(in[i] ^ gamma[i]);
        }
        return out;
    }


    /**
     * copy from <b>input</b> array <b>size</b> bytes with <b>offset</b>
     *
     * @param input  input byte array
     * @param size   count bytes to copy
     * @param offset <b>inputs</b> offset
     * @return
     */
    public static byte[] copyFromInput(byte[] input, int size, int offset)
    {

        if (input.length < (size + offset))
        {
            size = input.length - offset;
        }

        byte[] newIn = new byte[size];
        System.arraycopy(input, offset, newIn, 0, size);
        return newIn;
    }
}
