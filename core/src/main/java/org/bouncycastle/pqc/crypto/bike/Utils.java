package org.bouncycastle.pqc.crypto.bike;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Pack;

class Utils
{
    static byte[] xorBytes(byte[] a, byte[] b, int size){
        byte[] out = new byte[size];

        for (int i =0; i<size; i++)
        {
            out[i] = (byte)(a[i] ^ b[i]);
        }
        return out;
    }

    static int getHammingWeight(byte[] bytes){
        int hammingWeight = 0;
        for (int i =0; i <bytes.length; i++){
            hammingWeight += bytes[i];
        }
        return hammingWeight;
    }

    static void fromByteArrayToBitArray(byte[] out, byte[] in)
    {
        int max = (out.length / 8);
        for (int i = 0; i < max; i++)
        {
            for (int j = 0; j != 8; j++)
            {
                out[i * 8 + j] = (byte)((in[i] & (1 << j)) >>> j);
            }
        }
        if (out.length % 8 != 0)
        {
            int off = max * 8;
            int count = 0;
            while (off < out.length)
            {
                out[off++] = (byte)((in[max] & (1 << count)) >>> count);
                count++;
            }
        }
    }

    static void fromBitArrayToByteArray(byte[] out, byte[] in)
    {
        int count = 0;
        int pos = 0;
        long len = in.length;
        while (count < len)
        {
            if (count + 8 >= in.length)
            {// last set of bits cannot have enough 8 bits
                int b = in[count];
                for (int j = in.length - count - 1; j >= 1; j--)
                { //bin in reversed order
                    b |= in[count + j] << j;
                }
                out[pos] = (byte)b;
            }
            else
            {
                int b = in[count];
                for (int j = 7; j >= 1; j--)
                { //bin in reversed order
                    b |= in[count + j] << j;
                }
                out[pos] = (byte)b;
            }

            count += 8;
            pos++;
        }
    }

    static void fromLongArrayToByte16Array(int[] output, long[] input) {
        for (int i = 0; i != input.length; i++) {
            output[4 * i] = (int) input[i] & 0xffff;
            output[4 * i + 1] = (int) (input[i] >>> 16) & 0xffff;
            output[4 * i + 2] = (int) (input[i] >>> 32) & 0xffff;
            output[4 * i + 3] = (int) (input[i] >>> 48) & 0xffff;
        }
    }

    static void fromByteArrayToByte16Array(int[] output, byte[] input) {
        byte[] tmp = input;
        if (input.length % 2 != 0) {
            tmp = new byte[((input.length + 1) / 2) * 2];
            System.arraycopy(input, 0, tmp, 0, input.length);
        }

        int off = 0;
        for (int i = 0; i < output.length; i++) {
            output[i] = (int) Pack.littleEndianToShort(tmp, off) & 0xffff;
            off += 2;
        }
    }

    static void fromByte16ArrayToLongArray(long[] output, int[] input) {
        for (int i = 0; i != input.length; i += 4) {
            output[i / 4] = (long) input[i] & 0xffffL;
            output[i / 4] |= (long) input[i + 1] << 16;
            output[i / 4] |= (long) input[i + 2] << 32;
            output[i / 4] |= (long) input[i + 3] << 48;
        }
    }
    static void fromLongArrayToBitArray(byte[] output, long[] input)
    {
        int max = (output.length / 64);
        for (int i = 0; i < max; i++)
        {
            for (int j = 0; j != 64; j++)
            {
                output[i * 64 + j] = (byte)((input[i] & (1L << j)) >>> j);
            }
        }
        if (output.length % 64 != 0)
        {
            int off = max * 64;
            int count = 0;
            while (off < output.length)
            {
                output[off++] = (byte)((input[max] & (1L << count)) >>> count);
                count++;
            }
        }
    }

    static void fromLongArrayToBitIntArray(int[] output, long[] input)
    {
        int max = (output.length / 64);
        for (int i = 0; i < max; i++)
        {
            for (int j = 0; j != 64; j++)
            {
                output[i * 64 + j] = (byte)((input[i] & (1L << j)) >>> j);
            }
        }
        if (output.length % 64 != 0)
        {
            int off = max * 64;
            int count = 0;
            while (off < output.length)
            {
                output[off++] = (byte)((input[max] & (1L << count)) >>> count);
                count++;
            }
        }
    }

    static byte[] append0s(byte[] in, int length){
        byte[] out = new byte[length];
        System.arraycopy(in, 0, out, 0, in.length);
        return out;
    }

    static long bitMask(long a, long b) {
        return ((1L << (a % b)) - 1);
    }
    static void fromBitArrayToLongArray(long[] output, byte[] input)
    {
        int count = 0;
        int pos = 0;
        long len = input.length;
        while (count < len)
        {
            if (count + 64 >= input.length)
            {// last set of bits cannot have enough 64 bits
                long b = input[count];
                for (int j = input.length - count - 1; j >= 1; j--)
                { //bin in reversed order
                    b |= (long) input[count + j] << j;
                }
                output[pos] = b;
            }
            else
            {
                long b = input[count];
                for (int j = 63; j >= 1; j--)
                { //bin in reversed order
                    b |= (long) input[count + j] << j;
                }
                output[pos] = b;
            }

            count += 64;
            pos++;
        }
    }
    static byte[] convertIntArrayToBitArray(int[] input)
    {
        byte[] res = new byte[input.length];
        for (int i = 0; i < input.length; i++)
        {
            res[i] = (byte)input[i];
        }
        return res;
    }
    static int[] convertBitArrayToIntArray(byte[] input)
    {
        int[] res = new int[input.length];
        for (int i = 0; i < input.length; i++)
        {
            res[i] = input[i];
        }
        return res;
    }

    static int[] getPos1(byte[] input)
    {
        List<Integer> result = new ArrayList<Integer>();
        for (int i = 0; i < input.length; i++)
        {
            if (input[i] == 1)
            {
                result.add(i);
            }
        }
        int[] ret = new int[result.size()];
        for (int i=0; i < ret.length; i++)
        {
            ret[i] = result.get(i).intValue();
        }
        return ret;
    }

    static void fromByteArrayToLongArray(long[] out, byte[] in) {
        byte[] tmp = in;
        if (in.length % 8 != 0) {
            tmp = new byte[((in.length + 7) / 8) * 8];
            System.arraycopy(in, 0, tmp, 0, in.length);
        }

        int off = 0;
        for (int i = 0; i < out.length; i++) {
            out[i] = Pack.littleEndianToLong(tmp, off);
            off += 8;
        }
    }
    static void fromLongArrayToByteArray(byte[] output, long[] input)
    {
        int max = output.length / 8;
        for (int i = 0; i != max; i++)
        {
            Pack.longToLittleEndian(input[i], output, i * 8);
        }

        if (output.length % 8 != 0)
        {
            int off = max * 8;
            int count = 0;
            while (off < output.length)
            {
                output[off++] = (byte)(input[max] >>> (count++ * 8));
            }
        }
    }
    static int toUnsigned8bits(int a)
    {
        return a & 0xff;
    }

    static int toUnsigned16Bits(int a)
    {
        return a & 0xffff;
    }

}
