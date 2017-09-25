package org.bouncycastle.crypto.util;

import org.bouncycastle.util.Arrays;

/**
 * Some methods for GOST 3412 cipher algorithm
 */
public class GOST3412CipherUtil {


    /**
     * copy first <b>size</b> elements from <b>from</b>
     *
     * @param from source array
     * @param size size of new array
     * @return
     */
    public static byte[] MSB(byte[] from, int size) {
        return Arrays.copyOf(from, size);
    }


    /**
     * copy last <b>size</b> elements from <b>from</b>
     *
     * @param from source array
     * @param size size of new array
     * @return
     */
    public static byte[] LSB(byte[] from, int size) {
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
    public static byte[] sum(byte[] in, byte[] gamma) {

        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) (in[i] ^ gamma[i]);
        }
        return out;
    }

}
