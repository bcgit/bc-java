package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * Reference implementation of national ukrainian standard of hashing transformation DSTU7564.
 * Thanks to Roman Oliynykov' native C implementation:
 * https://github.com/Roman-Oliynykov/Kupyna-reference
 */
public class DSTU7564Digest
    implements ExtendedDigest, Memoable
{
    /* Number of 8-byte words in operating state for <= 256-bit hash codes */
    private static final int NB_512 = 8;

    /* Number of 8-byte words in operating state for <= 512-bit hash codes */
    private static final int NB_1024 = 16;

    /* Number of rounds for 512-bit state */
    private static final int NR_512 = 10;

    /* Number of rounds for 1024-bit state */
    private static final int NR_1024 = 14;

    private final CryptoServicePurpose purpose;

    private int hashSize;
    private int blockSize;

    private int columns;
    private int rounds;

    private long[] state;
    private long[] tempState1;
    private long[] tempState2;
    private long[] tempBuf;

    // TODO Guard against 'inputBlocks' overflow (2^64 blocks)
    private long inputBlocks;
    private int bufOff;
    private byte[] buf;

    public DSTU7564Digest(DSTU7564Digest digest)
    {
        this.purpose = digest.purpose;

        copyIn(digest);

        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    private void copyIn(DSTU7564Digest digest)
    {
        this.hashSize = digest.hashSize;
        this.blockSize = digest.blockSize;

        this.rounds = digest.rounds;
        if (columns > 0 && columns == digest.columns)
        {
            System.arraycopy(digest.state, 0, state, 0, columns);
            System.arraycopy(digest.buf, 0, buf, 0, blockSize);
        }
        else
        {
            this.columns = digest.columns;
            this.state = Arrays.clone(digest.state);
            this.tempState1 = new long[columns];
            this.tempState2 = new long[columns];
            this.tempBuf = new long[columns];
            this.buf = Arrays.clone(digest.buf);
        }

        this.inputBlocks = digest.inputBlocks;
        this.bufOff = digest.bufOff;
    }

    public DSTU7564Digest(int hashSizeBits)
    {
        this(hashSizeBits, CryptoServicePurpose.ANY);
    }

    public DSTU7564Digest(int hashSizeBits, CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
        
        if (hashSizeBits == 256 || hashSizeBits == 384 || hashSizeBits == 512)
        {
            this.hashSize = hashSizeBits >>> 3;
        }
        else
        {
            throw new IllegalArgumentException("Hash size is not recommended. Use 256/384/512 instead");
        }

        if (hashSizeBits > 256)
        {
            this.columns = NB_1024;
            this.rounds = NR_1024;
        }
        else
        {
            this.columns = NB_512;
            this.rounds = NR_512;
        }

        this.blockSize = columns << 3;

        this.state = new long[columns];
        this.state[0] = blockSize;

        this.tempState1 = new long[columns];
        this.tempState2 = new long[columns];
        this.tempBuf = new long[columns];

        this.buf = new byte[blockSize];

        CryptoServicesRegistrar.checkConstraints(cryptoServiceProperties());
    }

    public String getAlgorithmName()
    {
        return "DSTU7564";
    }

    public int getDigestSize()
    {
        return hashSize;
    }

    public int getByteLength()
    {
        return blockSize;
    }

    public void update(byte in)
    {
        buf[bufOff++] = in;
        if (bufOff == blockSize)
        {
            processBlock(buf, 0);
            bufOff = 0;
            ++inputBlocks;
        }
    }

    public void update(byte[] in, int inOff, int len)
    {
        while (bufOff != 0 && len > 0)
        {
            update(in[inOff++]);
            --len;
        }

        if (len > 0)
        {
            while (len >= blockSize)
            {
                processBlock(in, inOff);
                inOff += blockSize;
                len -= blockSize;
                ++inputBlocks;
            }

            while (len > 0)
            {
                update(in[inOff++]);
                --len;
            }
        }
    }

    public int doFinal(byte[] out, int outOff)
    {
        // Apply padding: terminator byte and 96-bit length field
        {
            int inputBytes = bufOff;
            buf[bufOff++] = (byte)0x80;

            int lenPos = blockSize - 12;
            if (bufOff > lenPos)
            {
                while (bufOff < blockSize)
                {
                    buf[bufOff++] = 0;
                }
                bufOff = 0;
                processBlock(buf, 0);
            }

            while (bufOff < lenPos)
            {
                buf[bufOff++] = 0;
            }

            long c = ((inputBlocks & 0xFFFFFFFFL) * blockSize + inputBytes) << 3;
            Pack.intToLittleEndian((int)c, buf, bufOff);
            bufOff += 4;
            c >>>= 32;
            c += ((inputBlocks >>> 32) * blockSize) << 3;
            Pack.longToLittleEndian(c, buf, bufOff);
//            bufOff += 8;
            processBlock(buf, 0);
        }

        {
            System.arraycopy(state, 0, tempState1, 0, columns);

            P(tempState1);

            for (int col = 0; col < columns; ++col)
            {
                state[col] ^= tempState1[col];
            }
        }

        int neededColumns = hashSize >>> 3;
        for (int col = columns - neededColumns; col < columns; ++col)
        {
            Pack.longToLittleEndian(state[col], out, outOff);
            outOff += 8;
        }

        reset();

        return hashSize;
    }

    public void reset()
    {
        Arrays.fill(state, 0L);
        state[0] = blockSize;

        inputBlocks = 0;
        bufOff = 0;
    }

    private void processBlock(byte[] input, int inOff)
    {
        int pos = inOff;
        for (int col = 0; col < columns; ++col)
        {
            long word = Pack.littleEndianToLong(input, pos);
            pos += 8;

            tempState1[col] = state[col] ^ word;
            tempState2[col] = word;
        }

        P(tempState1);
        Q(tempState2);

        for (int col = 0; col < columns; ++col)
        {
            state[col] ^= tempState1[col] ^ tempState2[col];
        }
    }

    private void P(long[] s)
    {
        for (int round = 0; round < rounds; ++round)
        {
            long rc = round;

            /* AddRoundConstants */
            for (int col = 0; col < columns; ++col)
            {
                s[col] ^= rc;
                rc += 0x10L;
            }

            /* shiftRows + subBytes + mixColumns, fused into T-table lookups */
            transform(s);
        }
    }

    private void Q(long[] s)
    {
        for (int round = 0; round < rounds; ++round)
        {
            /* AddRoundConstantsQ */
            long rc = ((long)(((columns - 1) << 4) ^ round) << 56) | 0x00F0F0F0F0F0F0F3L;

            for (int col = 0; col < columns; ++col)
            {
                s[col] += rc;
                rc -= 0x1000000000000000L;
            }

            /* shiftRows + subBytes + mixColumns, fused into T-table lookups */
            transform(s);
        }
    }

    /*
     * Fused shiftRows + subBytes + mixColumns. Each output column is the XOR of eight
     * precomputed T-table entries (Whirlpool C0..C7 form): T_k folds the row-k S-box and the
     * mixColumn contribution of byte position k, while shiftRows is folded into the source-column
     * selection. Row r of an output column is drawn from input column (col - shift[r]) mod columns,
     * with shift = {0,1,2,3,4,5,6,7} for the 512-bit state and {0,1,2,3,4,5,6,11} for the 1024-bit
     * state (only row 7 differs). columns is a power of two, so the modulo is a mask.
     */
    private void transform(long[] s)
    {
        long[] t = tempBuf;
        System.arraycopy(s, 0, t, 0, columns);

        int mask = columns - 1;
        int s7 = columns == NB_512 ? 7 : 11;

        for (int col = 0; col < columns; ++col)
        {
            s[col] = T0[(int)t[col] & 0xFF]
                ^ T1[(int)(t[(col - 1) & mask] >>> 8) & 0xFF]
                ^ T2[(int)(t[(col - 2) & mask] >>> 16) & 0xFF]
                ^ T3[(int)(t[(col - 3) & mask] >>> 24) & 0xFF]
                ^ T4[(int)(t[(col - 4) & mask] >>> 32) & 0xFF]
                ^ T5[(int)(t[(col - 5) & mask] >>> 40) & 0xFF]
                ^ T6[(int)(t[(col - 6) & mask] >>> 48) & 0xFF]
                ^ T7[(int)(t[(col - s7) & mask] >>> 56) & 0xFF];
        }
    }

    private static long mixColumn(long c)
    {
//        // Calculate column multiplied by powers of 'x'
//        long x0 = c;
//        long x1 = ((x0 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x0 & 0x8080808080808080L) >>> 7) * 0x1DL);
//        long x2 = ((x1 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x1 & 0x8080808080808080L) >>> 7) * 0x1DL);
//        long x3 = ((x2 & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((x2 & 0x8080808080808080L) >>> 7) * 0x1DL);
//
//        // Calculate products with circulant matrix from (0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04)
//        long m0 = x0;
//        long m1 = x0;
//        long m2 = x0 ^ x2;
//        long m3 = x0;
//        long m4 = x3;
//        long m5 = x1 ^ x2;
//        long m6 = x0 ^ x1 ^ x2;
//        long m7 = x2;
//
//        // Assemble the rotated products
//        return m0
//            ^ rotate(8, m1)
//            ^ rotate(16, m2)
//            ^ rotate(24, m3)
//            ^ rotate(32, m4)
//            ^ rotate(40, m5)
//            ^ rotate(48, m6)
//            ^ rotate(56, m7);

        // Multiply elements by 'x'
        long x1 = ((c & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((c & 0x8080808080808080L) >>> 7) * 0x1DL);
        long u, v;

        u  = rotate(8, c) ^ c;
        u ^= rotate(16, u);
        u ^= rotate(48, c);

        v  = u ^ c ^ x1;

        // Multiply elements by 'x^2'
        v  = ((v & 0x3F3F3F3F3F3F3F3FL) << 2) ^ (((v & 0x8080808080808080L) >>> 6) * 0x1DL) ^ (((v & 0x4040404040404040L) >>> 6) * 0x1DL);

        return u ^ rotate(32, v) ^ rotate(40, x1) ^ rotate(48, x1);
    }

    private static long rotate(int n, long x)
    {
        return (x >>> n) | (x << -n);
    }

    private static final byte[] S0 = new byte[]{ (byte)0xa8, (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75,
        (byte)0x6c, (byte)0x59, (byte)0x71, (byte)0xdf, (byte)0x87, (byte)0x95, (byte)0x17, (byte)0xf0, (byte)0xd8,
        (byte)0x09, (byte)0x6d, (byte)0xf3, (byte)0x1d, (byte)0xcb, (byte)0xc9, (byte)0x4d, (byte)0x2c, (byte)0xaf,
        (byte)0x79, (byte)0xe0, (byte)0x97, (byte)0xfd, (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39, (byte)0x3e,
        (byte)0xdd, (byte)0xa3, (byte)0x4f, (byte)0xb4, (byte)0xb6, (byte)0x9a, (byte)0x0e, (byte)0x1f, (byte)0xbf,
        (byte)0x15, (byte)0xe1, (byte)0x49, (byte)0xd2, (byte)0x93, (byte)0xc6, (byte)0x92, (byte)0x72, (byte)0x9e,
        (byte)0x61, (byte)0xd1, (byte)0x63, (byte)0xfa, (byte)0xee, (byte)0xf4, (byte)0x19, (byte)0xd5, (byte)0xad,
        (byte)0x58, (byte)0xa4, (byte)0xbb, (byte)0xa1, (byte)0xdc, (byte)0xf2, (byte)0x83, (byte)0x37, (byte)0x42,
        (byte)0xe4, (byte)0x7a, (byte)0x32, (byte)0x9c, (byte)0xcc, (byte)0xab, (byte)0x4a, (byte)0x8f, (byte)0x6e,
        (byte)0x04, (byte)0x27, (byte)0x2e, (byte)0xe7, (byte)0xe2, (byte)0x5a, (byte)0x96, (byte)0x16, (byte)0x23,
        (byte)0x2b, (byte)0xc2, (byte)0x65, (byte)0x66, (byte)0x0f, (byte)0xbc, (byte)0xa9, (byte)0x47, (byte)0x41,
        (byte)0x34, (byte)0x48, (byte)0xfc, (byte)0xb7, (byte)0x6a, (byte)0x88, (byte)0xa5, (byte)0x53, (byte)0x86,
        (byte)0xf9, (byte)0x5b, (byte)0xdb, (byte)0x38, (byte)0x7b, (byte)0xc3, (byte)0x1e, (byte)0x22, (byte)0x33,
        (byte)0x24, (byte)0x28, (byte)0x36, (byte)0xc7, (byte)0xb2, (byte)0x3b, (byte)0x8e, (byte)0x77, (byte)0xba,
        (byte)0xf5, (byte)0x14, (byte)0x9f, (byte)0x08, (byte)0x55, (byte)0x9b, (byte)0x4c, (byte)0xfe, (byte)0x60,
        (byte)0x5c, (byte)0xda, (byte)0x18, (byte)0x46, (byte)0xcd, (byte)0x7d, (byte)0x21, (byte)0xb0, (byte)0x3f,
        (byte)0x1b, (byte)0x89, (byte)0xff, (byte)0xeb, (byte)0x84, (byte)0x69, (byte)0x3a, (byte)0x9d, (byte)0xd7,
        (byte)0xd3, (byte)0x70, (byte)0x67, (byte)0x40, (byte)0xb5, (byte)0xde, (byte)0x5d, (byte)0x30, (byte)0x91,
        (byte)0xb1, (byte)0x78, (byte)0x11, (byte)0x01, (byte)0xe5, (byte)0x00, (byte)0x68, (byte)0x98, (byte)0xa0,
        (byte)0xc5, (byte)0x02, (byte)0xa6, (byte)0x74, (byte)0x2d, (byte)0x0b, (byte)0xa2, (byte)0x76, (byte)0xb3,
        (byte)0xbe, (byte)0xce, (byte)0xbd, (byte)0xae, (byte)0xe9, (byte)0x8a, (byte)0x31, (byte)0x1c, (byte)0xec,
        (byte)0xf1, (byte)0x99, (byte)0x94, (byte)0xaa, (byte)0xf6, (byte)0x26, (byte)0x2f, (byte)0xef, (byte)0xe8,
        (byte)0x8c, (byte)0x35, (byte)0x03, (byte)0xd4, (byte)0x7f, (byte)0xfb, (byte)0x05, (byte)0xc1, (byte)0x5e,
        (byte)0x90, (byte)0x20, (byte)0x3d, (byte)0x82, (byte)0xf7, (byte)0xea, (byte)0x0a, (byte)0x0d, (byte)0x7e,
        (byte)0xf8, (byte)0x50, (byte)0x1a, (byte)0xc4, (byte)0x07, (byte)0x57, (byte)0xb8, (byte)0x3c, (byte)0x62,
        (byte)0xe3, (byte)0xc8, (byte)0xac, (byte)0x52, (byte)0x64, (byte)0x10, (byte)0xd0, (byte)0xd9, (byte)0x13,
        (byte)0x0c, (byte)0x12, (byte)0x29, (byte)0x51, (byte)0xb9, (byte)0xcf, (byte)0xd6, (byte)0x73, (byte)0x8d,
        (byte)0x81, (byte)0x54, (byte)0xc0, (byte)0xed, (byte)0x4e, (byte)0x44, (byte)0xa7, (byte)0x2a, (byte)0x85,
        (byte)0x25, (byte)0xe6, (byte)0xca, (byte)0x7c, (byte)0x8b, (byte)0x56, (byte)0x80 };

    private static final byte[] S1 = new byte[]{ (byte)0xce, (byte)0xbb, (byte)0xeb, (byte)0x92, (byte)0xea, (byte)0xcb,
        (byte)0x13, (byte)0xc1, (byte)0xe9, (byte)0x3a, (byte)0xd6, (byte)0xb2, (byte)0xd2, (byte)0x90, (byte)0x17,
        (byte)0xf8, (byte)0x42, (byte)0x15, (byte)0x56, (byte)0xb4, (byte)0x65, (byte)0x1c, (byte)0x88, (byte)0x43,
        (byte)0xc5, (byte)0x5c, (byte)0x36, (byte)0xba, (byte)0xf5, (byte)0x57, (byte)0x67, (byte)0x8d, (byte)0x31,
        (byte)0xf6, (byte)0x64, (byte)0x58, (byte)0x9e, (byte)0xf4, (byte)0x22, (byte)0xaa, (byte)0x75, (byte)0x0f,
        (byte)0x02, (byte)0xb1, (byte)0xdf, (byte)0x6d, (byte)0x73, (byte)0x4d, (byte)0x7c, (byte)0x26, (byte)0x2e,
        (byte)0xf7, (byte)0x08, (byte)0x5d, (byte)0x44, (byte)0x3e, (byte)0x9f, (byte)0x14, (byte)0xc8, (byte)0xae,
        (byte)0x54, (byte)0x10, (byte)0xd8, (byte)0xbc, (byte)0x1a, (byte)0x6b, (byte)0x69, (byte)0xf3, (byte)0xbd,
        (byte)0x33, (byte)0xab, (byte)0xfa, (byte)0xd1, (byte)0x9b, (byte)0x68, (byte)0x4e, (byte)0x16, (byte)0x95,
        (byte)0x91, (byte)0xee, (byte)0x4c, (byte)0x63, (byte)0x8e, (byte)0x5b, (byte)0xcc, (byte)0x3c, (byte)0x19,
        (byte)0xa1, (byte)0x81, (byte)0x49, (byte)0x7b, (byte)0xd9, (byte)0x6f, (byte)0x37, (byte)0x60, (byte)0xca,
        (byte)0xe7, (byte)0x2b, (byte)0x48, (byte)0xfd, (byte)0x96, (byte)0x45, (byte)0xfc, (byte)0x41, (byte)0x12,
        (byte)0x0d, (byte)0x79, (byte)0xe5, (byte)0x89, (byte)0x8c, (byte)0xe3, (byte)0x20, (byte)0x30, (byte)0xdc,
        (byte)0xb7, (byte)0x6c, (byte)0x4a, (byte)0xb5, (byte)0x3f, (byte)0x97, (byte)0xd4, (byte)0x62, (byte)0x2d,
        (byte)0x06, (byte)0xa4, (byte)0xa5, (byte)0x83, (byte)0x5f, (byte)0x2a, (byte)0xda, (byte)0xc9, (byte)0x00,
        (byte)0x7e, (byte)0xa2, (byte)0x55, (byte)0xbf, (byte)0x11, (byte)0xd5, (byte)0x9c, (byte)0xcf, (byte)0x0e,
        (byte)0x0a, (byte)0x3d, (byte)0x51, (byte)0x7d, (byte)0x93, (byte)0x1b, (byte)0xfe, (byte)0xc4, (byte)0x47,
        (byte)0x09, (byte)0x86, (byte)0x0b, (byte)0x8f, (byte)0x9d, (byte)0x6a, (byte)0x07, (byte)0xb9, (byte)0xb0,
        (byte)0x98, (byte)0x18, (byte)0x32, (byte)0x71, (byte)0x4b, (byte)0xef, (byte)0x3b, (byte)0x70, (byte)0xa0,
        (byte)0xe4, (byte)0x40, (byte)0xff, (byte)0xc3, (byte)0xa9, (byte)0xe6, (byte)0x78, (byte)0xf9, (byte)0x8b,
        (byte)0x46, (byte)0x80, (byte)0x1e, (byte)0x38, (byte)0xe1, (byte)0xb8, (byte)0xa8, (byte)0xe0, (byte)0x0c,
        (byte)0x23, (byte)0x76, (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05, (byte)0xf1, (byte)0x6e, (byte)0x94,
        (byte)0x28, (byte)0x9a, (byte)0x84, (byte)0xe8, (byte)0xa3, (byte)0x4f, (byte)0x77, (byte)0xd3, (byte)0x85,
        (byte)0xe2, (byte)0x52, (byte)0xf2, (byte)0x82, (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53,
        (byte)0xb3, (byte)0x61, (byte)0xaf, (byte)0x39, (byte)0x35, (byte)0xde, (byte)0xcd, (byte)0x1f, (byte)0x99,
        (byte)0xac, (byte)0xad, (byte)0x72, (byte)0x2c, (byte)0xdd, (byte)0xd0, (byte)0x87, (byte)0xbe, (byte)0x5e,
        (byte)0xa6, (byte)0xec, (byte)0x04, (byte)0xc6, (byte)0x03, (byte)0x34, (byte)0xfb, (byte)0xdb, (byte)0x59,
        (byte)0xb6, (byte)0xc2, (byte)0x01, (byte)0xf0, (byte)0x5a, (byte)0xed, (byte)0xa7, (byte)0x66, (byte)0x21,
        (byte)0x7f, (byte)0x8a, (byte)0x27, (byte)0xc7, (byte)0xc0, (byte)0x29, (byte)0xd7 };

    private static final byte[] S2 = new byte[]{ (byte)0x93, (byte)0xd9, (byte)0x9a, (byte)0xb5, (byte)0x98, (byte)0x22,
        (byte)0x45, (byte)0xfc, (byte)0xba, (byte)0x6a, (byte)0xdf, (byte)0x02, (byte)0x9f, (byte)0xdc, (byte)0x51,
        (byte)0x59, (byte)0x4a, (byte)0x17, (byte)0x2b, (byte)0xc2, (byte)0x94, (byte)0xf4, (byte)0xbb, (byte)0xa3,
        (byte)0x62, (byte)0xe4, (byte)0x71, (byte)0xd4, (byte)0xcd, (byte)0x70, (byte)0x16, (byte)0xe1, (byte)0x49,
        (byte)0x3c, (byte)0xc0, (byte)0xd8, (byte)0x5c, (byte)0x9b, (byte)0xad, (byte)0x85, (byte)0x53, (byte)0xa1,
        (byte)0x7a, (byte)0xc8, (byte)0x2d, (byte)0xe0, (byte)0xd1, (byte)0x72, (byte)0xa6, (byte)0x2c, (byte)0xc4,
        (byte)0xe3, (byte)0x76, (byte)0x78, (byte)0xb7, (byte)0xb4, (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41,
        (byte)0x4c, (byte)0xde, (byte)0xb2, (byte)0x90, (byte)0x25, (byte)0xa5, (byte)0xd7, (byte)0x03, (byte)0x11,
        (byte)0x00, (byte)0xc3, (byte)0x2e, (byte)0x92, (byte)0xef, (byte)0x4e, (byte)0x12, (byte)0x9d, (byte)0x7d,
        (byte)0xcb, (byte)0x35, (byte)0x10, (byte)0xd5, (byte)0x4f, (byte)0x9e, (byte)0x4d, (byte)0xa9, (byte)0x55,
        (byte)0xc6, (byte)0xd0, (byte)0x7b, (byte)0x18, (byte)0x97, (byte)0xd3, (byte)0x36, (byte)0xe6, (byte)0x48,
        (byte)0x56, (byte)0x81, (byte)0x8f, (byte)0x77, (byte)0xcc, (byte)0x9c, (byte)0xb9, (byte)0xe2, (byte)0xac,
        (byte)0xb8, (byte)0x2f, (byte)0x15, (byte)0xa4, (byte)0x7c, (byte)0xda, (byte)0x38, (byte)0x1e, (byte)0x0b,
        (byte)0x05, (byte)0xd6, (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e, (byte)0x66, (byte)0xfd, (byte)0xb1,
        (byte)0xe5, (byte)0x60, (byte)0xaf, (byte)0x5e, (byte)0x33, (byte)0x87, (byte)0xc9, (byte)0xf0, (byte)0x5d,
        (byte)0x6d, (byte)0x3f, (byte)0x88, (byte)0x8d, (byte)0xc7, (byte)0xf7, (byte)0x1d, (byte)0xe9, (byte)0xec,
        (byte)0xed, (byte)0x80, (byte)0x29, (byte)0x27, (byte)0xcf, (byte)0x99, (byte)0xa8, (byte)0x50, (byte)0x0f,
        (byte)0x37, (byte)0x24, (byte)0x28, (byte)0x30, (byte)0x95, (byte)0xd2, (byte)0x3e, (byte)0x5b, (byte)0x40,
        (byte)0x83, (byte)0xb3, (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, (byte)0x8a, (byte)0xbc,
        (byte)0x20, (byte)0xeb, (byte)0xce, (byte)0x8e, (byte)0xab, (byte)0xee, (byte)0x31, (byte)0xa2, (byte)0x73,
        (byte)0xf9, (byte)0xca, (byte)0x3a, (byte)0x1a, (byte)0xfb, (byte)0x0d, (byte)0xc1, (byte)0xfe, (byte)0xfa,
        (byte)0xf2, (byte)0x6f, (byte)0xbd, (byte)0x96, (byte)0xdd, (byte)0x43, (byte)0x52, (byte)0xb6, (byte)0x08,
        (byte)0xf3, (byte)0xae, (byte)0xbe, (byte)0x19, (byte)0x89, (byte)0x32, (byte)0x26, (byte)0xb0, (byte)0xea,
        (byte)0x4b, (byte)0x64, (byte)0x84, (byte)0x82, (byte)0x6b, (byte)0xf5, (byte)0x79, (byte)0xbf, (byte)0x01,
        (byte)0x5f, (byte)0x75, (byte)0x63, (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65,
        (byte)0xe8, (byte)0x91, (byte)0xf6, (byte)0xff, (byte)0x13, (byte)0x58, (byte)0xf1, (byte)0x47, (byte)0x0a,
        (byte)0x7f, (byte)0xc5, (byte)0xa7, (byte)0xe7, (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44,
        (byte)0x42, (byte)0x04, (byte)0xa0, (byte)0xdb, (byte)0x39, (byte)0x86, (byte)0x54, (byte)0xaa, (byte)0x8c,
        (byte)0x34, (byte)0x21, (byte)0x8b, (byte)0xf8, (byte)0x0c, (byte)0x74, (byte)0x67 };

    private static final byte[] S3 = new byte[]{ (byte)0x68, (byte)0x8d, (byte)0xca, (byte)0x4d, (byte)0x73, (byte)0x4b,
        (byte)0x4e, (byte)0x2a, (byte)0xd4, (byte)0x52, (byte)0x26, (byte)0xb3, (byte)0x54, (byte)0x1e, (byte)0x19,
        (byte)0x1f, (byte)0x22, (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, (byte)0x83,
        (byte)0x13, (byte)0x8a, (byte)0xb7, (byte)0xd5, (byte)0x25, (byte)0x79, (byte)0xf5, (byte)0xbd, (byte)0x58,
        (byte)0x2f, (byte)0x0d, (byte)0x02, (byte)0xed, (byte)0x51, (byte)0x9e, (byte)0x11, (byte)0xf2, (byte)0x3e,
        (byte)0x55, (byte)0x5e, (byte)0xd1, (byte)0x16, (byte)0x3c, (byte)0x66, (byte)0x70, (byte)0x5d, (byte)0xf3,
        (byte)0x45, (byte)0x40, (byte)0xcc, (byte)0xe8, (byte)0x94, (byte)0x56, (byte)0x08, (byte)0xce, (byte)0x1a,
        (byte)0x3a, (byte)0xd2, (byte)0xe1, (byte)0xdf, (byte)0xb5, (byte)0x38, (byte)0x6e, (byte)0x0e, (byte)0xe5,
        (byte)0xf4, (byte)0xf9, (byte)0x86, (byte)0xe9, (byte)0x4f, (byte)0xd6, (byte)0x85, (byte)0x23, (byte)0xcf,
        (byte)0x32, (byte)0x99, (byte)0x31, (byte)0x14, (byte)0xae, (byte)0xee, (byte)0xc8, (byte)0x48, (byte)0xd3,
        (byte)0x30, (byte)0xa1, (byte)0x92, (byte)0x41, (byte)0xb1, (byte)0x18, (byte)0xc4, (byte)0x2c, (byte)0x71,
        (byte)0x72, (byte)0x44, (byte)0x15, (byte)0xfd, (byte)0x37, (byte)0xbe, (byte)0x5f, (byte)0xaa, (byte)0x9b,
        (byte)0x88, (byte)0xd8, (byte)0xab, (byte)0x89, (byte)0x9c, (byte)0xfa, (byte)0x60, (byte)0xea, (byte)0xbc,
        (byte)0x62, (byte)0x0c, (byte)0x24, (byte)0xa6, (byte)0xa8, (byte)0xec, (byte)0x67, (byte)0x20, (byte)0xdb,
        (byte)0x7c, (byte)0x28, (byte)0xdd, (byte)0xac, (byte)0x5b, (byte)0x34, (byte)0x7e, (byte)0x10, (byte)0xf1,
        (byte)0x7b, (byte)0x8f, (byte)0x63, (byte)0xa0, (byte)0x05, (byte)0x9a, (byte)0x43, (byte)0x77, (byte)0x21,
        (byte)0xbf, (byte)0x27, (byte)0x09, (byte)0xc3, (byte)0x9f, (byte)0xb6, (byte)0xd7, (byte)0x29, (byte)0xc2,
        (byte)0xeb, (byte)0xc0, (byte)0xa4, (byte)0x8b, (byte)0x8c, (byte)0x1d, (byte)0xfb, (byte)0xff, (byte)0xc1,
        (byte)0xb2, (byte)0x97, (byte)0x2e, (byte)0xf8, (byte)0x65, (byte)0xf6, (byte)0x75, (byte)0x07, (byte)0x04,
        (byte)0x49, (byte)0x33, (byte)0xe4, (byte)0xd9, (byte)0xb9, (byte)0xd0, (byte)0x42, (byte)0xc7, (byte)0x6c,
        (byte)0x90, (byte)0x00, (byte)0x8e, (byte)0x6f, (byte)0x50, (byte)0x01, (byte)0xc5, (byte)0xda, (byte)0x47,
        (byte)0x3f, (byte)0xcd, (byte)0x69, (byte)0xa2, (byte)0xe2, (byte)0x7a, (byte)0xa7, (byte)0xc6, (byte)0x93,
        (byte)0x0f, (byte)0x0a, (byte)0x06, (byte)0xe6, (byte)0x2b, (byte)0x96, (byte)0xa3, (byte)0x1c, (byte)0xaf,
        (byte)0x6a, (byte)0x12, (byte)0x84, (byte)0x39, (byte)0xe7, (byte)0xb0, (byte)0x82, (byte)0xf7, (byte)0xfe,
        (byte)0x9d, (byte)0x87, (byte)0x5c, (byte)0x81, (byte)0x35, (byte)0xde, (byte)0xb4, (byte)0xa5, (byte)0xfc,
        (byte)0x80, (byte)0xef, (byte)0xcb, (byte)0xbb, (byte)0x6b, (byte)0x76, (byte)0xba, (byte)0x5a, (byte)0x7d,
        (byte)0x78, (byte)0x0b, (byte)0x95, (byte)0xe3, (byte)0xad, (byte)0x74, (byte)0x98, (byte)0x3b, (byte)0x36,
        (byte)0x64, (byte)0x6d, (byte)0xdc, (byte)0xf0, (byte)0x59, (byte)0xa9, (byte)0x4c, (byte)0x17, (byte)0x7f,
        (byte)0x91, (byte)0xb8, (byte)0xc9, (byte)0x57, (byte)0x1b, (byte)0xe0, (byte)0x61 };

    /*
     * T-tables fusing subBytes and mixColumns (Whirlpool C0..C7 form). T_k[b] places the row-k
     * S-box image of b at byte position k and applies the MDS mixColumn, so that the combined
     * subBytes + mixColumns of a column equals the XOR of the eight T_k[byte_k] lookups; shiftRows
     * is folded into the source-column selection in transform(). Rows 0/4 use S0, 1/5 S1, 2/6 S2,
     * 3/7 S3 (matching the original subBytes byte-position mapping).
     */
    private static final long[] T0 = new long[256];
    private static final long[] T1 = new long[256];
    private static final long[] T2 = new long[256];
    private static final long[] T3 = new long[256];
    private static final long[] T4 = new long[256];
    private static final long[] T5 = new long[256];
    private static final long[] T6 = new long[256];
    private static final long[] T7 = new long[256];

    static
    {
        for (int b = 0; b < 256; ++b)
        {
            T0[b] = mixColumn((long)(S0[b] & 0xFF));
            T1[b] = mixColumn((long)(S1[b] & 0xFF) << 8);
            T2[b] = mixColumn((long)(S2[b] & 0xFF) << 16);
            T3[b] = mixColumn((long)(S3[b] & 0xFF) << 24);
            T4[b] = mixColumn((long)(S0[b] & 0xFF) << 32);
            T5[b] = mixColumn((long)(S1[b] & 0xFF) << 40);
            T6[b] = mixColumn((long)(S2[b] & 0xFF) << 48);
            T7[b] = mixColumn((long)(S3[b] & 0xFF) << 56);
        }
    }

    public Memoable copy()
    {
        return new DSTU7564Digest(this);
    }

    public void reset(Memoable other)
    {
        DSTU7564Digest d = (DSTU7564Digest)other;

        copyIn(d);
    }

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return Utils.getDefaultProperties(this, 256, purpose);
    }
}
