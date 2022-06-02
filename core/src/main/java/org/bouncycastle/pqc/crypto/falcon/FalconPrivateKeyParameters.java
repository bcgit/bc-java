package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPrivateKeyParameters
    extends FalconKeyParameters
{

    private byte[] encoded;

    public FalconPrivateKeyParameters(FalconParameters param, byte[] privateKey)
    {
        super(true, param);
        this.encoded = privateKey;
    }

    FalconPrivateKeyParameters(FalconParameters param, FalconSmallPoly f, FalconSmallPoly g, FalconSmallPoly F)
    {
        super(true, param);
        int logn = this.getParam().getLogn();
        int n = 1 << logn;
        int byte_size = (8 + (fg_bitsize[logn] * n * 2) + (8 * n)) / 8;
        this.encoded = new byte[byte_size];
        // write header byte - 0 1 0 1 logn
        this.encoded[0] = (byte)(80 + logn);
        // write rest of data
        int current = 1;
        current = trim_encode(current, this.encoded, f.coeffs, logn, fg_bitsize[logn]);
        current = trim_encode(current, this.encoded, g.coeffs, logn, fg_bitsize[logn]);
        current = trim_encode(current, this.encoded, F.coeffs, logn, 8);
    }

    private static int trim_encode(int out, byte[] out_arr, byte[] in_arr, int logn, int bits)
    {
        int n = 1 << logn;
        int buf = out;
        int acc = 0;
        int acc_len = 0;
        int mask = (1 << bits) - 1;
        for (int u = 0; u < n; u++)
        {
            acc = (acc << bits) | (Byte.toUnsignedInt(in_arr[u]) & mask);
            acc_len += bits;
            while (acc_len >= 8)
            {
                acc_len -= 8;
                out_arr[buf++] = (byte)(acc >>> acc_len);
            }
        }
        if (acc_len > 0)
        {
            out_arr[buf++] = (byte)(acc << (8 - acc_len));
        }
        return buf;
    }

    private static void trim_decode(byte[] out_arr, int logn, int bits, int in, byte[] in_arr)
    {
        int n = 1 << logn;
        int buf = in;
        int u = 0;
        int acc = 0;
        int acc_len = 0;
        int mask1 = (1 << bits) - 1;
        int mask2 = 1 << (bits - 1);
        while (u < n)
        {
            acc = (acc << 8) | Byte.toUnsignedInt(in_arr[buf++]);
            acc_len += 8;
            while (acc_len >= bits && u < n)
            {
                int w;

                acc_len -= bits;
                w = (acc >>> acc_len) & mask1;
                w |= -(w & mask2);
                out_arr[u++] = (byte)w;
            }
        }
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }

    public byte[] getPrivateKey()
    {
        return Arrays.clone(encoded);
    }

    FalconSmallPoly get_f()
    {
        int logn = this.getParam().getLogn();
        int n = 1 << logn;
        byte[] f = new byte[n];
        int start = 1;
        trim_decode(f, logn, fg_bitsize[logn], start, this.encoded);
        return new FalconSmallPoly(f);
    }

    FalconSmallPoly get_g()
    {
        int logn = this.getParam().getLogn();
        int n = 1 << logn;
        byte[] g = new byte[n];
        int start = 1 + (fg_bitsize[logn] * n / 8);
        trim_decode(g, logn, fg_bitsize[logn], start, this.encoded);
        return new FalconSmallPoly(g);
    }

    FalconSmallPoly get_F()
    {
        int logn = this.getParam().getLogn();
        int n = 1 << logn;
        byte[] F = new byte[n];
        int start = 1 + (2 * fg_bitsize[logn] * n / 8);
        trim_decode(F, logn, 8, start, this.encoded);
        return new FalconSmallPoly(F);
    }

    FalconSmallPoly get_G()
    {
        // get F, f, g
        FalconSmallPoly
            f = this.get_f(),
            g = this.get_g(),
            F = this.get_F();
        int logn = this.getParam().getLogn();
        int n = 1 << logn;
        byte[] G = new byte[n];
        FalconNTT.complete_private(G, f.coeffs, g.coeffs, F.coeffs, logn);
        return new FalconSmallPoly(G);
    }

    private static final int[] fg_bitsize = {
        0, // logn = 0
        8, // 1
        8, // 2
        8, // 3
        8, // 4
        8, // 5
        7, // 6
        7, // 7
        6, // 8
        6, // 9
        5  // 10
    };
}
