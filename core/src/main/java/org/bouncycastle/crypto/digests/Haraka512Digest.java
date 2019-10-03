package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

/**
 * Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
 * <p>
 * Haraka512-256 with reference to Python Reference Impl from: https://github.com/kste/haraka
 * </p>
 */
public class Haraka512Digest
    extends HarakaBase
{
    private static byte[][] RC = new byte[][]{
        {(byte)0x06, (byte)0x84, (byte)0x70, (byte)0x4c, (byte)0xe6, (byte)0x20, (byte)0xc0, (byte)0x0a, (byte)0xb2, (byte)0xc5, (byte)0xfe, (byte)0xf0, (byte)0x75, (byte)0x81, (byte)0x7b, (byte)0x9d},
        {(byte)0x8b, (byte)0x66, (byte)0xb4, (byte)0xe1, (byte)0x88, (byte)0xf3, (byte)0xa0, (byte)0x6b, (byte)0x64, (byte)0x0f, (byte)0x6b, (byte)0xa4, (byte)0x2f, (byte)0x08, (byte)0xf7, (byte)0x17},
        {(byte)0x34, (byte)0x02, (byte)0xde, (byte)0x2d, (byte)0x53, (byte)0xf2, (byte)0x84, (byte)0x98, (byte)0xcf, (byte)0x02, (byte)0x9d, (byte)0x60, (byte)0x9f, (byte)0x02, (byte)0x91, (byte)0x14},
        {(byte)0x0e, (byte)0xd6, (byte)0xea, (byte)0xe6, (byte)0x2e, (byte)0x7b, (byte)0x4f, (byte)0x08, (byte)0xbb, (byte)0xf3, (byte)0xbc, (byte)0xaf, (byte)0xfd, (byte)0x5b, (byte)0x4f, (byte)0x79},
        {(byte)0xcb, (byte)0xcf, (byte)0xb0, (byte)0xcb, (byte)0x48, (byte)0x72, (byte)0x44, (byte)0x8b, (byte)0x79, (byte)0xee, (byte)0xcd, (byte)0x1c, (byte)0xbe, (byte)0x39, (byte)0x70, (byte)0x44},
        {(byte)0x7e, (byte)0xea, (byte)0xcd, (byte)0xee, (byte)0x6e, (byte)0x90, (byte)0x32, (byte)0xb7, (byte)0x8d, (byte)0x53, (byte)0x35, (byte)0xed, (byte)0x2b, (byte)0x8a, (byte)0x05, (byte)0x7b},
        {(byte)0x67, (byte)0xc2, (byte)0x8f, (byte)0x43, (byte)0x5e, (byte)0x2e, (byte)0x7c, (byte)0xd0, (byte)0xe2, (byte)0x41, (byte)0x27, (byte)0x61, (byte)0xda, (byte)0x4f, (byte)0xef, (byte)0x1b},
        {(byte)0x29, (byte)0x24, (byte)0xd9, (byte)0xb0, (byte)0xaf, (byte)0xca, (byte)0xcc, (byte)0x07, (byte)0x67, (byte)0x5f, (byte)0xfd, (byte)0xe2, (byte)0x1f, (byte)0xc7, (byte)0x0b, (byte)0x3b},
        {(byte)0xab, (byte)0x4d, (byte)0x63, (byte)0xf1, (byte)0xe6, (byte)0x86, (byte)0x7f, (byte)0xe9, (byte)0xec, (byte)0xdb, (byte)0x8f, (byte)0xca, (byte)0xb9, (byte)0xd4, (byte)0x65, (byte)0xee},
        {(byte)0x1c, (byte)0x30, (byte)0xbf, (byte)0x84, (byte)0xd4, (byte)0xb7, (byte)0xcd, (byte)0x64, (byte)0x5b, (byte)0x2a, (byte)0x40, (byte)0x4f, (byte)0xad, (byte)0x03, (byte)0x7e, (byte)0x33},
        {(byte)0xb2, (byte)0xcc, (byte)0x0b, (byte)0xb9, (byte)0x94, (byte)0x17, (byte)0x23, (byte)0xbf, (byte)0x69, (byte)0x02, (byte)0x8b, (byte)0x2e, (byte)0x8d, (byte)0xf6, (byte)0x98, (byte)0x00},
        {(byte)0xfa, (byte)0x04, (byte)0x78, (byte)0xa6, (byte)0xde, (byte)0x6f, (byte)0x55, (byte)0x72, (byte)0x4a, (byte)0xaa, (byte)0x9e, (byte)0xc8, (byte)0x5c, (byte)0x9d, (byte)0x2d, (byte)0x8a},
        {(byte)0xdf, (byte)0xb4, (byte)0x9f, (byte)0x2b, (byte)0x6b, (byte)0x77, (byte)0x2a, (byte)0x12, (byte)0x0e, (byte)0xfa, (byte)0x4f, (byte)0x2e, (byte)0x29, (byte)0x12, (byte)0x9f, (byte)0xd4},
        {(byte)0x1e, (byte)0xa1, (byte)0x03, (byte)0x44, (byte)0xf4, (byte)0x49, (byte)0xa2, (byte)0x36, (byte)0x32, (byte)0xd6, (byte)0x11, (byte)0xae, (byte)0xbb, (byte)0x6a, (byte)0x12, (byte)0xee},
        {(byte)0xaf, (byte)0x04, (byte)0x49, (byte)0x88, (byte)0x4b, (byte)0x05, (byte)0x00, (byte)0x84, (byte)0x5f, (byte)0x96, (byte)0x00, (byte)0xc9, (byte)0x9c, (byte)0xa8, (byte)0xec, (byte)0xa6},
        {(byte)0x21, (byte)0x02, (byte)0x5e, (byte)0xd8, (byte)0x9d, (byte)0x19, (byte)0x9c, (byte)0x4f, (byte)0x78, (byte)0xa2, (byte)0xc7, (byte)0xe3, (byte)0x27, (byte)0xe5, (byte)0x93, (byte)0xec},
        {(byte)0xbf, (byte)0x3a, (byte)0xaa, (byte)0xf8, (byte)0xa7, (byte)0x59, (byte)0xc9, (byte)0xb7, (byte)0xb9, (byte)0x28, (byte)0x2e, (byte)0xcd, (byte)0x82, (byte)0xd4, (byte)0x01, (byte)0x73},
        {(byte)0x62, (byte)0x60, (byte)0x70, (byte)0x0d, (byte)0x61, (byte)0x86, (byte)0xb0, (byte)0x17, (byte)0x37, (byte)0xf2, (byte)0xef, (byte)0xd9, (byte)0x10, (byte)0x30, (byte)0x7d, (byte)0x6b},
        {(byte)0x5a, (byte)0xca, (byte)0x45, (byte)0xc2, (byte)0x21, (byte)0x30, (byte)0x04, (byte)0x43, (byte)0x81, (byte)0xc2, (byte)0x91, (byte)0x53, (byte)0xf6, (byte)0xfc, (byte)0x9a, (byte)0xc6},
        {(byte)0x92, (byte)0x23, (byte)0x97, (byte)0x3c, (byte)0x22, (byte)0x6b, (byte)0x68, (byte)0xbb, (byte)0x2c, (byte)0xaf, (byte)0x92, (byte)0xe8, (byte)0x36, (byte)0xd1, (byte)0x94, (byte)0x3a},
        {(byte)0xd3, (byte)0xbf, (byte)0x92, (byte)0x38, (byte)0x22, (byte)0x58, (byte)0x86, (byte)0xeb, (byte)0x6c, (byte)0xba, (byte)0xb9, (byte)0x58, (byte)0xe5, (byte)0x10, (byte)0x71, (byte)0xb4},
        {(byte)0xdb, (byte)0x86, (byte)0x3c, (byte)0xe5, (byte)0xae, (byte)0xf0, (byte)0xc6, (byte)0x77, (byte)0x93, (byte)0x3d, (byte)0xfd, (byte)0xdd, (byte)0x24, (byte)0xe1, (byte)0x12, (byte)0x8d},
        {(byte)0xbb, (byte)0x60, (byte)0x62, (byte)0x68, (byte)0xff, (byte)0xeb, (byte)0xa0, (byte)0x9c, (byte)0x83, (byte)0xe4, (byte)0x8d, (byte)0xe3, (byte)0xcb, (byte)0x22, (byte)0x12, (byte)0xb1},
        {(byte)0x73, (byte)0x4b, (byte)0xd3, (byte)0xdc, (byte)0xe2, (byte)0xe4, (byte)0xd1, (byte)0x9c, (byte)0x2d, (byte)0xb9, (byte)0x1a, (byte)0x4e, (byte)0xc7, (byte)0x2b, (byte)0xf7, (byte)0x7d},
        {(byte)0x43, (byte)0xbb, (byte)0x47, (byte)0xc3, (byte)0x61, (byte)0x30, (byte)0x1b, (byte)0x43, (byte)0x4b, (byte)0x14, (byte)0x15, (byte)0xc4, (byte)0x2c, (byte)0xb3, (byte)0x92, (byte)0x4e},
        {(byte)0xdb, (byte)0xa7, (byte)0x75, (byte)0xa8, (byte)0xe7, (byte)0x07, (byte)0xef, (byte)0xf6, (byte)0x03, (byte)0xb2, (byte)0x31, (byte)0xdd, (byte)0x16, (byte)0xeb, (byte)0x68, (byte)0x99},
        {(byte)0x6d, (byte)0xf3, (byte)0x61, (byte)0x4b, (byte)0x3c, (byte)0x75, (byte)0x59, (byte)0x77, (byte)0x8e, (byte)0x5e, (byte)0x23, (byte)0x02, (byte)0x7e, (byte)0xca, (byte)0x47, (byte)0x2c},
        {(byte)0xcd, (byte)0xa7, (byte)0x5a, (byte)0x17, (byte)0xd6, (byte)0xde, (byte)0x7d, (byte)0x77, (byte)0x6d, (byte)0x1b, (byte)0xe5, (byte)0xb9, (byte)0xb8, (byte)0x86, (byte)0x17, (byte)0xf9},
        {(byte)0xec, (byte)0x6b, (byte)0x43, (byte)0xf0, (byte)0x6b, (byte)0xa8, (byte)0xe9, (byte)0xaa, (byte)0x9d, (byte)0x6c, (byte)0x06, (byte)0x9d, (byte)0xa9, (byte)0x46, (byte)0xee, (byte)0x5d},
        {(byte)0xcb, (byte)0x1e, (byte)0x69, (byte)0x50, (byte)0xf9, (byte)0x57, (byte)0x33, (byte)0x2b, (byte)0xa2, (byte)0x53, (byte)0x11, (byte)0x59, (byte)0x3b, (byte)0xf3, (byte)0x27, (byte)0xc1},
        {(byte)0x2c, (byte)0xee, (byte)0x0c, (byte)0x75, (byte)0x00, (byte)0xda, (byte)0x61, (byte)0x9c, (byte)0xe4, (byte)0xed, (byte)0x03, (byte)0x53, (byte)0x60, (byte)0x0e, (byte)0xd0, (byte)0xd9},
        {(byte)0xf0, (byte)0xb1, (byte)0xa5, (byte)0xa1, (byte)0x96, (byte)0xe9, (byte)0x0c, (byte)0xab, (byte)0x80, (byte)0xbb, (byte)0xba, (byte)0xbc, (byte)0x63, (byte)0xa4, (byte)0xa3, (byte)0x50},
        {(byte)0xae, (byte)0x3d, (byte)0xb1, (byte)0x02, (byte)0x5e, (byte)0x96, (byte)0x29, (byte)0x88, (byte)0xab, (byte)0x0d, (byte)0xde, (byte)0x30, (byte)0x93, (byte)0x8d, (byte)0xca, (byte)0x39},
        {(byte)0x17, (byte)0xbb, (byte)0x8f, (byte)0x38, (byte)0xd5, (byte)0x54, (byte)0xa4, (byte)0x0b, (byte)0x88, (byte)0x14, (byte)0xf3, (byte)0xa8, (byte)0x2e, (byte)0x75, (byte)0xb4, (byte)0x42},
        {(byte)0x34, (byte)0xbb, (byte)0x8a, (byte)0x5b, (byte)0x5f, (byte)0x42, (byte)0x7f, (byte)0xd7, (byte)0xae, (byte)0xb6, (byte)0xb7, (byte)0x79, (byte)0x36, (byte)0x0a, (byte)0x16, (byte)0xf6},
        {(byte)0x26, (byte)0xf6, (byte)0x52, (byte)0x41, (byte)0xcb, (byte)0xe5, (byte)0x54, (byte)0x38, (byte)0x43, (byte)0xce, (byte)0x59, (byte)0x18, (byte)0xff, (byte)0xba, (byte)0xaf, (byte)0xde},
        {(byte)0x4c, (byte)0xe9, (byte)0x9a, (byte)0x54, (byte)0xb9, (byte)0xf3, (byte)0x02, (byte)0x6a, (byte)0xa2, (byte)0xca, (byte)0x9c, (byte)0xf7, (byte)0x83, (byte)0x9e, (byte)0xc9, (byte)0x78},
        {(byte)0xae, (byte)0x51, (byte)0xa5, (byte)0x1a, (byte)0x1b, (byte)0xdf, (byte)0xf7, (byte)0xbe, (byte)0x40, (byte)0xc0, (byte)0x6e, (byte)0x28, (byte)0x22, (byte)0x90, (byte)0x12, (byte)0x35},
        {(byte)0xa0, (byte)0xc1, (byte)0x61, (byte)0x3c, (byte)0xba, (byte)0x7e, (byte)0xd2, (byte)0x2b, (byte)0xc1, (byte)0x73, (byte)0xbc, (byte)0x0f, (byte)0x48, (byte)0xa6, (byte)0x59, (byte)0xcf},
        {(byte)0x75, (byte)0x6a, (byte)0xcc, (byte)0x03, (byte)0x02, (byte)0x28, (byte)0x82, (byte)0x88, (byte)0x4a, (byte)0xd6, (byte)0xbd, (byte)0xfd, (byte)0xe9, (byte)0xc5, (byte)0x9d, (byte)0xa1}
    };

    private final byte[] buffer;
    private int off;

    public Haraka512Digest()
    {
        this.buffer = new byte[64];
    }

    public Haraka512Digest(Haraka512Digest digest)
    {
        this.buffer = Arrays.clone(digest.buffer);
        this.off = digest.off;
    }

    private void mix512(byte[][] s1, byte[][] s2)
    {
        System.arraycopy(s1[0], 12, s2[0], 0, 4);
        System.arraycopy(s1[2], 12, s2[0], 4, 4);
        System.arraycopy(s1[1], 12, s2[0], 8, 4);
        System.arraycopy(s1[3], 12, s2[0], 12, 4);

        System.arraycopy(s1[2], 0, s2[1], 0, 4);
        System.arraycopy(s1[0], 0, s2[1], 4, 4);
        System.arraycopy(s1[3], 0, s2[1], 8, 4);
        System.arraycopy(s1[1], 0, s2[1], 12, 4);

        System.arraycopy(s1[2], 4, s2[2], 0, 4);
        System.arraycopy(s1[0], 4, s2[2], 4, 4);
        System.arraycopy(s1[3], 4, s2[2], 8, 4);
        System.arraycopy(s1[1], 4, s2[2], 12, 4);

        System.arraycopy(s1[0], 8, s2[3], 0, 4);
        System.arraycopy(s1[2], 8, s2[3], 4, 4);
        System.arraycopy(s1[1], 8, s2[3], 8, 4);
        System.arraycopy(s1[3], 8, s2[3], 12, 4);
    }

    private int haraka512256(byte[] msg, byte[] out, int outOff)
    {
        byte[][] s1 = new byte[4][16];
        byte[][] s2 = new byte[4][16];

        //-- Unrolled version of above.

        System.arraycopy(msg, 0, s1[0], 0, 16);
        System.arraycopy(msg, 16, s1[1], 0, 16);
        System.arraycopy(msg, 32, s1[2], 0, 16);
        System.arraycopy(msg, 48, s1[3], 0, 16);

        s1[0] = aesEnc(s1[0], RC[0]);
        s1[1] = aesEnc(s1[1], RC[1]);
        s1[2] = aesEnc(s1[2], RC[2]);
        s1[3] = aesEnc(s1[3], RC[3]);
        s1[0] = aesEnc(s1[0], RC[4]);
        s1[1] = aesEnc(s1[1], RC[5]);
        s1[2] = aesEnc(s1[2], RC[6]);
        s1[3] = aesEnc(s1[3], RC[7]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[8]);
        s1[1] = aesEnc(s2[1], RC[9]);
        s1[2] = aesEnc(s2[2], RC[10]);
        s1[3] = aesEnc(s2[3], RC[11]);
        s1[0] = aesEnc(s1[0], RC[12]);
        s1[1] = aesEnc(s1[1], RC[13]);
        s1[2] = aesEnc(s1[2], RC[14]);
        s1[3] = aesEnc(s1[3], RC[15]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[16]);
        s1[1] = aesEnc(s2[1], RC[17]);
        s1[2] = aesEnc(s2[2], RC[18]);
        s1[3] = aesEnc(s2[3], RC[19]);
        s1[0] = aesEnc(s1[0], RC[20]);
        s1[1] = aesEnc(s1[1], RC[21]);
        s1[2] = aesEnc(s1[2], RC[22]);
        s1[3] = aesEnc(s1[3], RC[23]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[24]);
        s1[1] = aesEnc(s2[1], RC[25]);
        s1[2] = aesEnc(s2[2], RC[26]);
        s1[3] = aesEnc(s2[3], RC[27]);
        s1[0] = aesEnc(s1[0], RC[28]);
        s1[1] = aesEnc(s1[1], RC[29]);
        s1[2] = aesEnc(s1[2], RC[30]);
        s1[3] = aesEnc(s1[3], RC[31]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[32]);
        s1[1] = aesEnc(s2[1], RC[33]);
        s1[2] = aesEnc(s2[2], RC[34]);
        s1[3] = aesEnc(s2[3], RC[35]);
        s1[0] = aesEnc(s1[0], RC[36]);
        s1[1] = aesEnc(s1[1], RC[37]);
        s1[2] = aesEnc(s1[2], RC[38]);
        s1[3] = aesEnc(s1[3], RC[39]);
        mix512(s1, s2);

        s1[0] = xor(s2[0], msg, 0);
        s1[1] = xor(s2[1], msg, 16);
        s1[2] = xor(s2[2], msg, 32);
        s1[3] = xor(s2[3], msg, 48);

        System.arraycopy(s1[0], 8, out, outOff, 8);
        System.arraycopy(s1[1], 8, out, outOff + 8, 8);
        System.arraycopy(s1[2], 0, out, outOff + 16, 8);
        System.arraycopy(s1[3], 0, out, outOff + 24, 8);

        return DIGEST_SIZE;
    }

    public String getAlgorithmName()
    {
        return "Haraka-512";
    }

    public void update(byte in)
    {
        if (off + 1 > 64)
        {
            throw new IllegalArgumentException("total input cannot be more than 64 bytes");
        }

        buffer[off++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (off + len > 64)
        {
            throw new IllegalArgumentException("total input cannot be more than 64 bytes");
        }

        System.arraycopy(in, inOff, buffer, off, len);
        off += len;
    }

    public int doFinal(byte[] out, int outOff)
    {
        if (off != 64)
        {
            throw new IllegalStateException("input must be exactly 64 bytes");
        }

        if (out.length - outOff < 32)
        {
            throw new IllegalArgumentException("output too short to receive digest");
        }

        int rv = haraka512256(buffer, out, outOff);

        reset();

        return rv;
    }

    public void reset()
    {
        off = 0;
        Arrays.clear(buffer);
    }
}
