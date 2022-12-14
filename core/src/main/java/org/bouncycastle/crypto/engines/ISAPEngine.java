package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;


import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;



public class ISAPEngine
    implements AEADBlockCipher
{
    public enum IsapType
    {
        ISAP_A_128A,
        ISAP_K_128A,
        ISAP_A_128,
        ISAP_K_128
    }

    public ISAPEngine(IsapType isapType)
    {
        switch (isapType)
        {
        case ISAP_A_128A:
            isap = new ISAP_A_128A();
            break;
        case ISAP_K_128A:
            isap = new ISAP_K_128A();
            break;
        case ISAP_A_128:
            isap = new ISAP_A_128();
            break;
        case ISAP_K_128:
            isap = new ISAP_K_128();
            break;
        }
    }

    final int CRYPTO_KEYBYTES = 16;
    final int CRYPTO_NPUBBYTES = 16;
    final int ISAP_STATE_SZ = 40;

    private byte[] k;
    private byte[] c;
    private byte[] ad;
    private byte[] npub;

    private byte[] message;

    final int[][] R = {{19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41}};

    private long x0, x1, x2, x3, x4;
    private long t0, t1, t2, t3, t4;
    int ISAP_rH;
    int ISAP_rH_SZ;

    private final short[] KeccakF400RoundConstants = {
        (short)0x0001,
        (short)0x8082,
        (short)0x808a,
        (short)0x8000,
        (short)0x808b,
        (short)0x0001,
        (short)0x8081,
        (short)0x8009,
        (short)0x008a,
        (short)0x0088,
        (short)0x8009,
        (short)0x000a,
        (short)0x808b,
        (short)0x008b,
        (short)0x8089,
        (short)0x8003,
        (short)0x8002,
        (short)0x0080,
        (short)0x800a,
        (short)0x000a,
    };

    private Isap isap;

    private interface Isap
    {
        void isap_enc(byte[] k, byte[] npub, byte[] m, int mlen, byte[] c, int clen);

        void isap_mac(byte[] k, byte[] npub, byte[] ad, int adlen, byte[] c, int clen, byte[] tag);
    }

    private class ISAP_A_128A
        implements Isap
    {
        final byte[] ISAP_IV1 = {0x01, (byte)128, 64, 1, 12, 1, 6, 12};
        final byte[] ISAP_IV2 = {0x02, (byte)128, 64, 1, 12, 1, 6, 12};
        final byte[] ISAP_IV3 = {0x03, (byte)128, 64, 1, 12, 1, 6, 12};

        public ISAP_A_128A()
        {
            ISAP_rH = 64;
            ISAP_rH_SZ = ((ISAP_rH + 7) / 8);
        }

        public void isap_enc(byte[] k, byte[] npub, byte[] m, int mlen, byte[] c, int clen)
        {
            long[] state64 = new long[getLongSize(ISAP_STATE_SZ)];
            // Init state
            long[] npub64;
            if (npub != null)
            {
                npub64 = new long[getLongSize(npub.length)];
                Pack.littleEndianToLong(npub, 0, npub64, 0, npub64.length);
            }
            else
            {
                npub64 = new long[0];
            }
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV364 = new long[getLongSize(ISAP_IV3.length)];
            Pack.littleEndianToLong(ISAP_IV3, 0, ISAP_IV364, 0, ISAP_IV364.length);
            isap_rk(k64, ISAP_IV364, npub, CRYPTO_NPUBBYTES, state64, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
            t0 = t1 = t2 = t3 = t4 = 0;
            x0 = U64BIG(state64[0]);
            x1 = U64BIG(state64[1]);
            x2 = U64BIG(state64[2]);
            x3 = U64BIG(npub64[0]);
            x4 = U64BIG(npub64[1]);
            P6();

            /* Encrypt m */
            long[] m64 = new long[getLongSize(mlen)];
            littleEndianToLong(m, m64);
            long[] c64 = new long[getLongSize(clen)];
            littleEndianToLong(c, c64);
            int idx = 0;
            while (mlen >= ISAP_rH_SZ)
            {
                c64[idx] = U64BIG(x0) ^ m64[idx];
                P6();
                idx++;
                mlen -= ISAP_rH_SZ;
            }
            longToLittleEndian(c64, c);
            /* Encrypt final m block */
            byte[] xo = Pack.longToLittleEndian(x0);
            while (mlen > 0)
            {
                c[(idx << 3) + mlen - 1] = (byte)(xo[ISAP_rH_SZ - mlen] ^ m[(idx << 3) + mlen - 1]);
                mlen--;
            }
        }

        public void isap_mac(byte[] k, byte[] npub, byte[] ad, int adlen, byte[] c, int clen, byte[] tag)
        {
            // Init State
            byte[] state = new byte[ISAP_STATE_SZ];
            long[] state64 = new long[getLongSize(ISAP_STATE_SZ)];
            long[] npub64;
            if (npub != null)
            {
                npub64 = new long[getLongSize(npub.length)];
                Pack.littleEndianToLong(npub, 0, npub64, 0, npub64.length);
            }
            else
            {
                npub64 = new long[0];
            }

            t0 = t1 = t2 = t3 = t4 = 0;

            // Init state
            x0 = U64BIG(npub64[0]);
            x1 = U64BIG(npub64[1]);
            //x2 = U64BIG(((u64 *)ISAP_IV1)[0]);
            x2 = U64BIG(Pack.littleEndianToLong(ISAP_IV1, 0));
            x3 = x4 = 0;
            P12();

            /* Absorb ad */
            long[] ad64 = new long[getLongSize(adlen)];
            littleEndianToLong(ad, ad64);
            int idx = 0;
            while (adlen >= ISAP_rH_SZ)
            {
                x0 ^= U64BIG(ad64[idx]);
                P12();
                idx++;
                adlen -= ISAP_rH_SZ;
            }

            /* Absorb final ad block */
            byte[] xo = Pack.longToLittleEndian(x0);
            xo[ISAP_rH_SZ - 1 - adlen] ^= 0x80;
            while (adlen > 0)
            {
                xo[ISAP_rH_SZ - adlen] ^= ad[(idx << 3) + adlen - 1];
                adlen--;
            }
            x0 = Pack.littleEndianToLong(xo, 0);
            P12();

            // Domain seperation
            x4 ^= 1L;

            /* Absorb c */
            long[] c64 = new long[getLongSize(clen)];
            littleEndianToLong(c, c64);
            idx = 0;
            while (clen >= ISAP_rH_SZ)
            {
                x0 ^= U64BIG(c64[idx]);
                P12();
                idx++;
                clen -= ISAP_rH_SZ;
            }

            /* Absorb final c block */
            xo = Pack.longToLittleEndian(x0);
            xo[ISAP_rH_SZ - 1 - clen] ^= 0x80;
            while (clen > 0)
            {
                xo[ISAP_rH_SZ - clen] ^= c[(idx << 3) + clen - 1];
                clen--;
            }
            x0 = Pack.littleEndianToLong(xo, 0);
            P12();

            // Derive K*
            Pack.longToLittleEndian(U64BIG(x0), state, 0);
            Pack.longToLittleEndian(U64BIG(x1), state, 8);
            Pack.longToLittleEndian(U64BIG(x2), state, 16);
            Pack.longToLittleEndian(U64BIG(x3), state, 24);
            Pack.longToLittleEndian(U64BIG(x4), state, 32);
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV264 = new long[getLongSize(ISAP_IV2.length)];
            Pack.littleEndianToLong(ISAP_IV2, 0, ISAP_IV264, 0, ISAP_IV264.length);
            isap_rk(k64, ISAP_IV264, state, CRYPTO_KEYBYTES, state64, CRYPTO_KEYBYTES);
            x0 = U64BIG(state64[0]);
            x1 = U64BIG(state64[1]);
            x2 = U64BIG(state64[2]);
            x3 = U64BIG(state64[3]);
            x4 = U64BIG(state64[4]);

            // Squeeze tag
            P12();
            long[] tag64 = new long[2];
            tag64[0] = U64BIG(x0);
            tag64[1] = U64BIG(x1);
            Pack.longToLittleEndian(tag64, 0, 2, tag, 0);
        }

        public void isap_rk(long[] k64, long[] iv64, byte[] y, int ylen, long[] out64, int outlen)
        {
            // Init state
            t0 = t1 = t2 = t3 = t4 = 0;
            x0 = U64BIG(k64[0]);
            x1 = U64BIG(k64[1]);
            x2 = U64BIG(iv64[0]);
            x3 = x4 = 0;
            P12();

            // Absorb Y
            int cur_byte_pos, cur_bit_pos;
            long cur_bit;
            for (int i = 0; i < (ylen << 3) - 1; i++)
            {
                cur_byte_pos = i >>> 3;
                cur_bit_pos = 7 - (i & 7);
                cur_bit = (((y[cur_byte_pos] >>> (cur_bit_pos)) & 0x01) << 7) & 0xFFL;
                x0 ^= (cur_bit) << 56;
                P1();
            }
            cur_bit = ((y[ylen - 1]) & 0x01) << 7;
            x0 ^= cur_bit << 56;
            P12();

            // Extract K*
            out64[0] = U64BIG(x0);
            out64[1] = U64BIG(x1);
            if (outlen == 24)
            {
                out64[2] = U64BIG(x2);
            }
            else
            {
                out64[2] = Pack.littleEndianToLong(y, 16);
                out64[3] = Pack.littleEndianToLong(y, 24);
                out64[4] = Pack.littleEndianToLong(y, 32);
            }

        }
    }

    private class ISAP_A_128
        implements Isap
    {
        final byte[] ISAP_IV1 = {0x01, (byte)128, 64, 1, 12, 12, 12, 12};
        final byte[] ISAP_IV2 = {0x02, (byte)128, 64, 1, 12, 12, 12, 12};
        final byte[] ISAP_IV3 = {0x03, (byte)128, 64, 1, 12, 12, 12, 12};

        public ISAP_A_128()
        {
            ISAP_rH = 64;
            ISAP_rH_SZ = ((ISAP_rH + 7) / 8);
        }

        private void ABSORB_MAC(byte[] src, int len)
        {
            int rem_bytes = len;
            long[] src64 = new long[getLongSize(src.length)];
            littleEndianToLong(src, src64);
            int idx64 = 0;
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
                    x0 ^= U64BIG(src64[idx64]);
                    idx64++;
                    P12();
                    rem_bytes -= ISAP_rH_SZ;
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    x0 ^= U64BIG(src64[idx64]);
                    P12();
                    x0 ^= 0x8000000000000000L;
                    P12();
                    break;
                }
                else
                {
                    long lane64;
                    byte[] lane8 = new byte[8];
                    int idx8 = idx64 << 3;
                    for (int i = 0; i < 8; i++)
                    {
                        if (i < (rem_bytes))
                        {
                            lane8[i] = src[idx8];
                            idx8++;
                        }
                        else if (i == rem_bytes)
                        {
                            lane8[i] = (byte)0x80;
                        }
                        else
                        {
                            lane8[i] = 0x00;
                        }
                    }
                    lane64 = Pack.littleEndianToLong(lane8, 0);
                    x0 ^= U64BIG(lane64);
                    P12();
                    break;
                }
            }
        }

        public void isap_enc(byte[] k, byte[] npub, byte[] m, int mlen, byte[] c, int clen)
        {
            long[] state64 = new long[getLongSize(ISAP_STATE_SZ)];
            // Init state
            long[] npub64;
            if (npub != null)
            {
                npub64 = new long[getLongSize(npub.length)];
                Pack.littleEndianToLong(npub, 0, npub64, 0, npub64.length);
            }
            else
            {
                npub64 = new long[0];
            }
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV364 = new long[getLongSize(ISAP_IV3.length)];
            Pack.littleEndianToLong(ISAP_IV3, 0, ISAP_IV364, 0, ISAP_IV364.length);
            isap_rk(k64, ISAP_IV364, npub, CRYPTO_NPUBBYTES, state64, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
            t0 = t1 = t2 = t3 = t4 = 0;
            x0 = U64BIG(state64[0]);
            x1 = U64BIG(state64[1]);
            x2 = U64BIG(state64[2]);
            x3 = U64BIG(npub64[0]);
            x4 = U64BIG(npub64[1]);
            P12();//difference against ISAP_128_A

            /* Encrypt m */
            long[] m64 = new long[getLongSize(mlen)];
            littleEndianToLong(m, m64);
            long[] c64 = new long[getLongSize(clen)];
            littleEndianToLong(c, c64);
            int idx64 = 0;
            int rem_bytes = mlen;
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
                    // Squeeze full lane
                    littleEndianToLong(c, c64);
                    c64[idx64] = U64BIG(x0) ^ m64[idx64];
                    idx64++;
                    P12();
                    rem_bytes -= ISAP_rH_SZ;
                    longToLittleEndian(c64, c);
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    // Squeeze full lane and stop
                    littleEndianToLong(c, c64);
                    c64[idx64] = U64BIG(x0) ^ m64[idx64];
                    longToLittleEndian(c64, c);
                    break;
                }
                else
                {
                    // Squeeze partial lane and stop
                    long lane64 = U64BIG(x0);
                    byte[] lane8 = Pack.longToLittleEndian(lane64);
                    int idx8 = idx64 << 3;
                    for (int i = 0; i < rem_bytes; i++)
                    {
                        c[idx8] = (byte)(lane8[i] ^ m[idx8]);
                        idx8++;
                    }
                    break;
                }
            }
        }

        public void isap_mac(byte[] k, byte[] npub, byte[] ad, int adlen, byte[] c, int clen, byte[] tag)
        {
            // Init State
            byte[] state = new byte[ISAP_STATE_SZ];
            long[] state64 = new long[getLongSize(ISAP_STATE_SZ)];
            long[] npub64;
            if (npub != null)
            {
                npub64 = new long[getLongSize(npub.length)];
                Pack.littleEndianToLong(npub, 0, npub64, 0, npub64.length);
            }
            else
            {
                npub64 = new long[0];
            }

            t0 = t1 = t2 = t3 = t4 = 0;

            // Init state
            x0 = U64BIG(npub64[0]);
            x1 = U64BIG(npub64[1]);
            //x2 = U64BIG(((u64 *)ISAP_IV1)[0]);
            x2 = U64BIG(Pack.littleEndianToLong(ISAP_IV1, 0));
            x3 = x4 = 0;
            P12();

            ABSORB_MAC(ad, adlen);

            // Domain seperation
            x4 ^= 1L;

            ABSORB_MAC(c, clen);

            // Derive K*
            Pack.longToLittleEndian(U64BIG(x0), state, 0);
            Pack.longToLittleEndian(U64BIG(x1), state, 8);
            Pack.longToLittleEndian(U64BIG(x2), state, 16);
            Pack.longToLittleEndian(U64BIG(x3), state, 24);
            Pack.longToLittleEndian(U64BIG(x4), state, 32);
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV264 = new long[getLongSize(ISAP_IV2.length)];
            Pack.littleEndianToLong(ISAP_IV2, 0, ISAP_IV264, 0, ISAP_IV264.length);
            isap_rk(k64, ISAP_IV264, state, CRYPTO_KEYBYTES, state64, CRYPTO_KEYBYTES);
            x0 = U64BIG(state64[0]);
            x1 = U64BIG(state64[1]);
            x2 = U64BIG(state64[2]);
            x3 = U64BIG(state64[3]);
            x4 = U64BIG(state64[4]);

            // Squeeze tag
            P12();
            long[] tag64 = new long[2];
            tag64[0] = U64BIG(x0);
            tag64[1] = U64BIG(x1);
            Pack.longToLittleEndian(tag64, 0, 2, tag, 0);
        }

        public void isap_rk(long[] k64, long[] iv64, byte[] y, int ylen, long[] out64, int outlen)
        {
            // Init state
            t0 = t1 = t2 = t3 = t4 = 0;
            x0 = U64BIG(k64[0]);
            x1 = U64BIG(k64[1]);
            x2 = U64BIG(iv64[0]);
            x3 = x4 = 0;
            P12();

            // Absorb Y
            int cur_byte_pos, cur_bit_pos;
            long cur_bit;
            for (int i = 0; i < (ylen << 3) - 1; i++)
            {
                cur_byte_pos = i >>> 3;
                cur_bit_pos = 7 - (i & 7);
                cur_bit = (((y[cur_byte_pos] >>> (cur_bit_pos)) & 0x01) << 7) & 0xFFL;
                x0 ^= (cur_bit) << 56;
                P12();//Difference against ISAP_A_128A
            }
            cur_bit = ((y[ylen - 1]) & 0x01) << 7;
            x0 ^= cur_bit << 56;
            P12();

            // Extract K*
            out64[0] = U64BIG(x0);
            out64[1] = U64BIG(x1);
            if (outlen == 24)
            {
                out64[2] = U64BIG(x2);
            }
            else
            {
                out64[2] = Pack.littleEndianToLong(y, 16);
                out64[3] = Pack.littleEndianToLong(y, 24);
                out64[4] = Pack.littleEndianToLong(y, 32);
            }
        }
    }

    private class ISAP_K_128A
        implements Isap
    {
        //public short SX[] = new short[25];
        final byte[] ISAP_IV1 = {0x01, (byte)128, (byte)144, 1, 16, 1, 8, 8};
        final byte[] ISAP_IV2 = {0x02, (byte)128, (byte)144, 1, 16, 1, 8, 8};
        final byte[] ISAP_IV3 = {0x03, (byte)128, (byte)144, 1, 16, 1, 8, 8};

        public ISAP_K_128A()
        {
            ISAP_rH = 144;
            ISAP_rH_SZ = ((ISAP_rH + 7) / 8);
        }

        private void ABSORB_MAC(short[] SX, byte[] src, int len, short[] E)
        {
            int rem_bytes = len;
            int idx = 0;
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
//                    S.l64[0] ^= *((UINT64 *) (src + idx + 0));
//                    S.l64[1] ^= *((UINT64 *) (src + idx + 8));
//                    S.l16[8] ^= *((UINT64 *) (src + idx + 16));
                    for (int i = 0; i < 9; ++i)
                    {
                        SX[i] ^= Pack.littleEndianToShort(src, idx + (i << 1));
                    }
                    idx += ISAP_rH_SZ;
                    rem_bytes -= ISAP_rH_SZ;
                    rounds16X(SX, E);
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    for (int i = 0; i < 9; ++i)
                    {
                        SX[i] ^= Pack.littleEndianToShort(src, idx + (i << 1));
                    }
                    rounds16X(SX, E);
                    SX[0] ^= 0x80;
                    rounds16X(SX, E);
                    break;
                }
                else
                {
                    for (int i = 0; i < ISAP_rH_SZ; i++)
                    {
                        if (i < rem_bytes)
                        {
                            SX[i >> 1] ^= (src[idx] & 0xFF) << ((i & 1) << 3);
                            idx++;
                        }
                        else if (i == rem_bytes)
                        {
                            SX[i >> 1] ^= 0x80 << ((i & 1) << 3);
                        }
                    }
                    rounds16X(SX, E);
                    break;
                }
            }
        }

        public void isap_enc(byte[] k, byte[] npub, byte[] m, int mlen, byte[] c, int clen)
        {
            long[] state64 = new long[getLongSize(ISAP_STATE_SZ)];
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV364 = new long[getLongSize(ISAP_IV3.length)];
            Pack.littleEndianToLong(ISAP_IV3, 0, ISAP_IV364, 0, ISAP_IV364.length);
            isap_rk(k64, ISAP_IV364, npub, CRYPTO_NPUBBYTES, state64, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
            short SX[] = new short[25];
            // Init state
            short[] E = new short[25];
            SX[0] = (short)state64[0];
            SX[1] = (short)(state64[0] >>> 16);
            SX[2] = (short)(state64[0] >>> 32);
            SX[3] = (short)(state64[0] >>> 48);
            SX[4] = (short)state64[1];
            SX[5] = (short)(state64[1] >>> 16);
            SX[6] = (short)(state64[1] >>> 32);
            SX[7] = (short)(state64[1] >>> 48);
            SX[8] = (short)state64[2];
            SX[9] = (short)(state64[2] >>> 16);
            SX[10] = (short)(state64[2] >>> 32);
            SX[11] = (short)(state64[2] >>> 48);
            SX[12] = (short)state64[3];
            SX[13] = (short)(state64[3] >>> 16);
            SX[14] = (short)(state64[3] >>> 32);
            SX[15] = (short)(state64[3] >>> 48);
            SX[16] = (short)state64[4];
            SX[17] = Pack.littleEndianToShort(npub, 0);
            SX[18] = Pack.littleEndianToShort(npub, 2);
            SX[19] = Pack.littleEndianToShort(npub, 4);
            SX[20] = Pack.littleEndianToShort(npub, 6);
            SX[21] = Pack.littleEndianToShort(npub, 8);
            SX[22] = Pack.littleEndianToShort(npub, 10);
            SX[23] = Pack.littleEndianToShort(npub, 12);
            SX[24] = Pack.littleEndianToShort(npub, 14);
            rounds8X(SX, E);

            // Squeeze key stream
            long rem_bytes = mlen;
            int idx = 0;
            long[] m64 = new long[getLongSize(mlen)];
            littleEndianToLong(m, m64);
            long[] c64 = new long[getLongSize(clen)];
            littleEndianToLong(c, c64);
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
                    // Squeeze full lane and continue
                    for (int i = 0; i < 18; ++i)
                    {
                        c[idx + i] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[idx + i]);
                    }
                    idx += ISAP_rH_SZ;
                    rem_bytes -= ISAP_rH_SZ;
                    rounds8X(SX, E);
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    // Squeeze full lane and stop
                    for (int i = 0; i < 18; ++i)
                    {
                        c[idx + i] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[idx + i]);
                    }
                    break;
                }
                else
                {
                    // Squeeze partial lane and stop
                    for (int i = 0; i < rem_bytes; ++i)
                    {
                        c[idx] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[idx]);
                        idx++;
                    }
                    break;
                }
            }
        }

        public void isap_rk(long[] k64, long[] iv64, byte[] y, int ylen, long[] out64, int outlen)
        {
            short[] k16 = longToShort(k64);
            short[] iv16 = longToShort(iv64);
            // Init state
            short[] SX = new short[25];
            short[] E = new short[25];
            SX[0] = k16[0];
            SX[1] = k16[1];
            SX[2] = k16[2];
            SX[3] = k16[3];
            SX[4] = k16[4];
            SX[5] = k16[5];
            SX[6] = k16[6];
            SX[7] = k16[7];
            SX[8] = iv16[0];
            SX[9] = iv16[1];
            SX[10] = iv16[2];
            SX[11] = iv16[3];
            rounds8X(SX, E);
            // Absorb all bits of Y
            for (int i = 0; i < ylen * 8 - 1; i++)
            {
                int cur_byte_pos = i / 8;
                int cur_bit_pos = 7 - (i % 8);
                short cur_bit = (short)(((y[cur_byte_pos] >>> (cur_bit_pos)) & 0x01) << 7);
                SX[0] ^= cur_bit;
                rounds1X(SX, E);
            }
            short cur_bit = (short)(((y[ylen - 1]) & 0x01) << 7);
            SX[0] ^= cur_bit;
            rounds8X(SX, E);

            // Extract K*
            out64[0] = shortToLong(SX, 0);
            out64[1] = shortToLong(SX, 4);
            if (outlen == ISAP_STATE_SZ - CRYPTO_NPUBBYTES)
            {
                out64[2] = shortToLong(SX, 8);
                out64[3] = shortToLong(SX, 12);
                out64[4] = SX[16];
            }
        }

        public void isap_mac(byte[] k, byte[] npub, byte[] ad, int adlen, byte[] c, int clen, byte[] tag)
        {
            short[] E = new short[25];
            short[] SX = new short[25];
            // Init state
            SX[0] = Pack.littleEndianToShort(npub, 0);
            SX[1] = Pack.littleEndianToShort(npub, 2);
            SX[2] = Pack.littleEndianToShort(npub, 4);
            SX[3] = Pack.littleEndianToShort(npub, 6);
            SX[4] = Pack.littleEndianToShort(npub, 8);
            SX[5] = Pack.littleEndianToShort(npub, 10);
            SX[6] = Pack.littleEndianToShort(npub, 12);
            SX[7] = Pack.littleEndianToShort(npub, 14);
            SX[8] = (short)((ISAP_IV1[0] & 0xFF) | ((ISAP_IV1[1] & 0xFF) << 8));
            SX[9] = (short)((ISAP_IV1[2] & 0xFF) | ((ISAP_IV1[3] & 0xFF) << 8));
            SX[10] = (short)((ISAP_IV1[4] & 0xFF) | ((ISAP_IV1[5] & 0xFF) << 8));
            SX[11] = (short)((ISAP_IV1[6] & 0xFF) | ((ISAP_IV1[7] & 0xFF) << 8));
            rounds16X(SX, E);

            // Absorb AD
            ABSORB_MAC(SX, ad, adlen, E);

            // Domain seperation
            SX[24] ^= 0x0100;

            // Absorb C
            ABSORB_MAC(SX, c, clen, E);

            // Derive K*
            byte[] y = new byte[16];
            Pack.shortToLittleEndian(SX[0], y, 0);
            Pack.shortToLittleEndian(SX[1], y, 2);
            Pack.shortToLittleEndian(SX[2], y, 4);
            Pack.shortToLittleEndian(SX[3], y, 6);
            Pack.shortToLittleEndian(SX[4], y, 8);
            Pack.shortToLittleEndian(SX[5], y, 10);
            Pack.shortToLittleEndian(SX[6], y, 12);
            Pack.shortToLittleEndian(SX[7], y, 14);
            long[] y64 = new long[4];
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV264 = new long[getLongSize(ISAP_IV3.length)];
            Pack.littleEndianToLong(ISAP_IV2, 0, ISAP_IV264, 0, ISAP_IV264.length);
            isap_rk(k64, ISAP_IV264, y, CRYPTO_KEYBYTES, y64, CRYPTO_KEYBYTES);
            SX[0] = (short)y64[0];
            SX[1] = (short)(y64[0] >>> 16);
            SX[2] = (short)(y64[0] >>> 32);
            SX[3] = (short)(y64[0] >>> 48);
            SX[4] = (short)y64[1];
            SX[5] = (short)(y64[1] >>> 16);
            SX[6] = (short)(y64[1] >>> 32);
            SX[7] = (short)(y64[1] >>> 48);

            // Squeeze tag
            rounds16X(SX, E);

            Pack.shortToLittleEndian(SX[0], tag, 0);
            Pack.shortToLittleEndian(SX[1], tag, 2);
            Pack.shortToLittleEndian(SX[2], tag, 4);
            Pack.shortToLittleEndian(SX[3], tag, 6);
            Pack.shortToLittleEndian(SX[4], tag, 8);
            Pack.shortToLittleEndian(SX[5], tag, 10);
            Pack.shortToLittleEndian(SX[6], tag, 12);
            Pack.shortToLittleEndian(SX[7], tag, 14);
        }
    }

    private class ISAP_K_128
        implements Isap
    {
        //public short SX[] = new short[25];
        final byte[] ISAP_IV1 = {0x01, (byte)128, (byte)144, 1, 20, 12, 12, 12};
        final byte[] ISAP_IV2 = {0x02, (byte)128, (byte)144, 1, 20, 12, 12, 12};
        final byte[] ISAP_IV3 = {0x03, (byte)128, (byte)144, 1, 20, 12, 12, 12};

        public ISAP_K_128()
        {
            ISAP_rH = 144;
            ISAP_rH_SZ = ((ISAP_rH + 7) / 8);
        }

        private void ABSORB_MAC(short[] SX, byte[] src, int len, short[] E)
        {
            int rem_bytes = len;
            int idx = 0;
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
                    for (int i = 0; i < 9; ++i)
                    {
                        SX[i] ^= Pack.littleEndianToShort(src, idx + (i << 1));
                    }
                    idx += ISAP_rH_SZ;
                    rem_bytes -= ISAP_rH_SZ;
                    rounds20X(SX, E);
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    for (int i = 0; i < 9; ++i)
                    {
                        SX[i] ^= Pack.littleEndianToShort(src, idx + (i << 1));
                    }
                    rounds20X(SX, E);
                    SX[0] ^= 0x80;
                    rounds20X(SX, E);
                    break;
                }
                else
                {
                    for (int i = 0; i < ISAP_rH_SZ; i++)
                    {
                        if (i < rem_bytes)
                        {
                            SX[i >> 1] ^= (src[idx] & 0xFF) << ((i & 1) << 3);
                            idx++;
                        }
                        else if (i == rem_bytes)
                        {
                            SX[i >> 1] ^= 0x80 << ((i & 1) << 3);
                        }
                    }
                    rounds20X(SX, E);
                    break;
                }
            }
        }

        public void isap_enc(byte[] k, byte[] npub, byte[] m, int mlen, byte[] c, int clen)
        {
            long[] state64 = new long[getLongSize(ISAP_STATE_SZ)];
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV364 = new long[getLongSize(ISAP_IV3.length)];
            Pack.littleEndianToLong(ISAP_IV3, 0, ISAP_IV364, 0, ISAP_IV364.length);
            isap_rk(k64, ISAP_IV364, npub, CRYPTO_NPUBBYTES, state64, ISAP_STATE_SZ - CRYPTO_NPUBBYTES);
            short SX[] = new short[25];
            // Init state
            short[] E = new short[25];
            SX[0] = (short)state64[0];
            SX[1] = (short)(state64[0] >>> 16);
            SX[2] = (short)(state64[0] >>> 32);
            SX[3] = (short)(state64[0] >>> 48);
            SX[4] = (short)state64[1];
            SX[5] = (short)(state64[1] >>> 16);
            SX[6] = (short)(state64[1] >>> 32);
            SX[7] = (short)(state64[1] >>> 48);
            SX[8] = (short)state64[2];
            SX[9] = (short)(state64[2] >>> 16);
            SX[10] = (short)(state64[2] >>> 32);
            SX[11] = (short)(state64[2] >>> 48);
            SX[12] = (short)state64[3];
            SX[13] = (short)(state64[3] >>> 16);
            SX[14] = (short)(state64[3] >>> 32);
            SX[15] = (short)(state64[3] >>> 48);
            SX[16] = (short)state64[4];
            SX[17] = Pack.littleEndianToShort(npub, 0);
            SX[18] = Pack.littleEndianToShort(npub, 2);
            SX[19] = Pack.littleEndianToShort(npub, 4);
            SX[20] = Pack.littleEndianToShort(npub, 6);
            SX[21] = Pack.littleEndianToShort(npub, 8);
            SX[22] = Pack.littleEndianToShort(npub, 10);
            SX[23] = Pack.littleEndianToShort(npub, 12);
            SX[24] = Pack.littleEndianToShort(npub, 14);
            rounds12X(SX, E);

            // Squeeze key stream
            long rem_bytes = mlen;
            int idx = 0;
            long[] m64 = new long[getLongSize(mlen)];
            littleEndianToLong(m, m64);
            long[] c64 = new long[getLongSize(clen)];
            littleEndianToLong(c, c64);
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
                    // Squeeze full lane and continue
                    for (int i = 0; i < 18; ++i)
                    {
                        c[idx + i] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[idx + i]);
                    }
                    idx += ISAP_rH_SZ;
                    rem_bytes -= ISAP_rH_SZ;
                    rounds12X(SX, E);
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    // Squeeze full lane and stop
                    for (int i = 0; i < 18; ++i)
                    {
                        c[idx + i] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[idx + i]);
                    }
                    break;
                }
                else
                {
                    // Squeeze partial lane and stop
                    for (int i = 0; i < rem_bytes; ++i)
                    {
                        c[idx] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[idx]);
                        idx++;
                    }
                    break;
                }
            }
        }

        public void isap_rk(long[] k64, long[] iv64, byte[] y, int ylen, long[] out64, int outlen)
        {
            short[] k16 = longToShort(k64);
            short[] iv16 = longToShort(iv64);
            // Init state
            short[] SX = new short[25];
            short[] E = new short[25];
            SX[0] = k16[0];
            SX[1] = k16[1];
            SX[2] = k16[2];
            SX[3] = k16[3];
            SX[4] = k16[4];
            SX[5] = k16[5];
            SX[6] = k16[6];
            SX[7] = k16[7];
            SX[8] = iv16[0];
            SX[9] = iv16[1];
            SX[10] = iv16[2];
            SX[11] = iv16[3];
            rounds12X(SX, E);
            // Absorb all bits of Y
            for (int i = 0; i < ylen * 8 - 1; i++)
            {
                int cur_byte_pos = i / 8;
                int cur_bit_pos = 7 - (i % 8);
                short cur_bit = (short)(((y[cur_byte_pos] >>> (cur_bit_pos)) & 0x01) << 7);
                SX[0] ^= cur_bit;
                rounds12X(SX, E);
            }
            short cur_bit = (short)(((y[ylen - 1]) & 0x01) << 7);
            SX[0] ^= cur_bit;
            rounds12X(SX, E);

            // Extract K*
            out64[0] = shortToLong(SX, 0);
            out64[1] = shortToLong(SX, 4);
            if (outlen == ISAP_STATE_SZ - CRYPTO_NPUBBYTES)
            {
                out64[2] = shortToLong(SX, 8);
                out64[3] = shortToLong(SX, 12);
                out64[4] = SX[16];
            }
        }

        public void isap_mac(byte[] k, byte[] npub, byte[] ad, int adlen, byte[] c, int clen, byte[] tag)
        {
            short[] E = new short[25];
            short[] SX = new short[25];
            // Init state
            SX[0] = Pack.littleEndianToShort(npub, 0);
            SX[1] = Pack.littleEndianToShort(npub, 2);
            SX[2] = Pack.littleEndianToShort(npub, 4);
            SX[3] = Pack.littleEndianToShort(npub, 6);
            SX[4] = Pack.littleEndianToShort(npub, 8);
            SX[5] = Pack.littleEndianToShort(npub, 10);
            SX[6] = Pack.littleEndianToShort(npub, 12);
            SX[7] = Pack.littleEndianToShort(npub, 14);
            SX[8] = (short)((ISAP_IV1[0] & 0xFF) | ((ISAP_IV1[1] & 0xFF) << 8));
            SX[9] = (short)((ISAP_IV1[2] & 0xFF) | ((ISAP_IV1[3] & 0xFF) << 8));
            SX[10] = (short)((ISAP_IV1[4] & 0xFF) | ((ISAP_IV1[5] & 0xFF) << 8));
            SX[11] = (short)((ISAP_IV1[6] & 0xFF) | ((ISAP_IV1[7] & 0xFF) << 8));
            rounds20X(SX, E);

            // Absorb AD
            ABSORB_MAC(SX, ad, adlen, E);

            // Domain seperation
            SX[24] ^= 0x0100;

            // Absorb C
            ABSORB_MAC(SX, c, clen, E);

            // Derive K*
            byte[] y = new byte[16];
            Pack.shortToLittleEndian(SX[0], y, 0);
            Pack.shortToLittleEndian(SX[1], y, 2);
            Pack.shortToLittleEndian(SX[2], y, 4);
            Pack.shortToLittleEndian(SX[3], y, 6);
            Pack.shortToLittleEndian(SX[4], y, 8);
            Pack.shortToLittleEndian(SX[5], y, 10);
            Pack.shortToLittleEndian(SX[6], y, 12);
            Pack.shortToLittleEndian(SX[7], y, 14);
            long[] y64 = new long[4];
            long[] k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            long[] ISAP_IV264 = new long[getLongSize(ISAP_IV3.length)];
            Pack.littleEndianToLong(ISAP_IV2, 0, ISAP_IV264, 0, ISAP_IV264.length);
            isap_rk(k64, ISAP_IV264, y, CRYPTO_KEYBYTES, y64, CRYPTO_KEYBYTES);
            SX[0] = (short)y64[0];
            SX[1] = (short)(y64[0] >>> 16);
            SX[2] = (short)(y64[0] >>> 32);
            SX[3] = (short)(y64[0] >>> 48);
            SX[4] = (short)y64[1];
            SX[5] = (short)(y64[1] >>> 16);
            SX[6] = (short)(y64[1] >>> 32);
            SX[7] = (short)(y64[1] >>> 48);

            // Squeeze tag
            rounds20X(SX, E);

            Pack.shortToLittleEndian(SX[0], tag, 0);
            Pack.shortToLittleEndian(SX[1], tag, 2);
            Pack.shortToLittleEndian(SX[2], tag, 4);
            Pack.shortToLittleEndian(SX[3], tag, 6);
            Pack.shortToLittleEndian(SX[4], tag, 8);
            Pack.shortToLittleEndian(SX[5], tag, 10);
            Pack.shortToLittleEndian(SX[6], tag, 12);
            Pack.shortToLittleEndian(SX[7], tag, 14);
        }
    }


    @Override
    public BlockCipher getUnderlyingCipher()
    {
        return null;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        /**
         * Grain encryption and decryption is completely symmetrical, so the
         * 'forEncryption' is irrelevant.
         */
//        if (!(params instanceof ParametersWithIV))
//        {
//            throw new IllegalArgumentException(
//                "Grain-128AEAD init parameters must include an IV");
//        }

        ParametersWithIV ivParams = (ParametersWithIV)params;

        byte[] iv = ivParams.getIV();

//        if (iv == null || iv.length != 12)
//        {
//            throw new IllegalArgumentException(
//                "Grain-128AEAD requires exactly 12 bytes of IV");
//        }
//
//        if (!(ivParams.getParameters() instanceof KeyParameter))
//        {
//            throw new IllegalArgumentException(
//                "Grain-128AEAD init parameters must include a key");
//        }

        KeyParameter key = (KeyParameter)ivParams.getParameters();
        byte[] keyBytes = key.getKey();
//        if (keyBytes.length != 16)
//        {
//            throw new IllegalArgumentException(
//                "Grain-128AEAD key must be 128 bits long");
//        }
//
//        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
//            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));

        /**
         * Initialize variables.
         */
        npub = new byte[iv.length];
        k = new byte[keyBytes.length];
        System.arraycopy(iv, 0, npub, 0, iv.length);
        System.arraycopy(keyBytes, 0, k, 0, keyBytes.length);
    }

    @Override
    public String getAlgorithmName()
    {
        return null;
    }

    @Override
    public void processAADByte(byte in)
    {

    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        //TODO:
        ad = in;
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return 0;
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        message = in;
        if (message.length > 0)
        {
            isap.isap_enc(k, npub, message, message.length, output, output.length);
        }
        c = output;
        return 0;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        //output.length:=input.length+ISAP_TAG_SZ;
        int adlen = 0;
        if (ad != null)
        {
            adlen = ad.length;
        }
        isap.isap_mac(k, npub, ad, adlen, c, c.length, output);
        return 0;
    }

    @Override
    public byte[] getMac()
    {
        return new byte[0];
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        return 0;
    }

    @Override
    public int getOutputSize(int len)
    {
        return 0;
    }

    @Override
    public void reset()
    {

    }

    private int getLongSize(int x)
    {
        return (x >>> 3) + ((x & 7) != 0 ? 1 : 0);
    }

    private short[] longToShort(long[] input)
    {
        short[] output = new short[input.length << 2];
        for (int i = 0; i < input.length; ++i)
        {
            output[i << 2] = (short)input[i];
            output[(i << 2) + 1] = (short)(input[i] >>> 16);
            output[(i << 2) + 2] = (short)(input[i] >>> 32);
            output[(i << 2) + 3] = (short)(input[i] >>> 48);
        }
        return output;
    }

    private void littleEndianToLong(byte[] input, long[] output)
    {
        Pack.littleEndianToLong(input, 0, output, 0, input.length >> 3);
        if ((input.length & 7) != 0)
        {
            for (int i = (input.length >> 3) << 3; i < input.length; ++i)
            {
                output[output.length - 1] |= (input[i] & 0xFFL) << ((i & 7) << 3);
            }
        }
    }

    private void longToLittleEndian(long[] input, byte[] output)
    {
        Pack.longToLittleEndian(input, 0, output.length >> 3, output, 0);
        if ((output.length & 7) != 0)
        {
            for (int i = (output.length >> 3) << 3; i < output.length; ++i)
            {
                output[i] = (byte)(input[input.length - 1] >>> ((i & 7) << 3));
            }
        }
    }

    private long shortToLong(short[] input, int inOff)
    {
        long res = 0;
        int len = Math.min(input.length - inOff, 4);
        for (int i = 0; i < len; ++i)
        {
            res |= (input[inOff++] & 0xFFFFL) << (i << 4);
        }
        return res;
    }

    private long U64BIG(long x)
    {
        return ((ROTR(x, 8) & (0xFF000000FF000000L)) | (ROTR(x, 24) & (0x00FF000000FF0000L)) |
            (ROTR(x, 40) & (0x0000FF000000FF00L)) | (ROTR(x, 56) & (0x000000FF000000FFL)));
    }

    private short ROL16(short a, int offset)
    {
        return (short)(((a & 0xFFFF) << offset) ^ ((a & 0xFFFF) >>> (16 - offset)));
    }

    private long ROTR(long x, long n)
    {
        return (x >>> n) | (x << (64 - n));
    }

    private void ROUND(long C)
    {
        x2 ^= C;
        x0 ^= x4;
        x4 ^= x3;
        x2 ^= x1;
        t0 = x0;
        t4 = x4;
        t3 = x3;
        t1 = x1;
        t2 = x2;
        x0 = t0 ^ ((~t1) & t2);
        x2 = t2 ^ ((~t3) & t4);
        x4 = t4 ^ ((~t0) & t1);
        x1 = t1 ^ ((~t2) & t3);
        x3 = t3 ^ ((~t4) & t0);
        x1 ^= x0;
        t1 = x1;
        x1 = ROTR(x1, R[1][0]);
        x3 ^= x2;
        t2 = x2;
        x2 = ROTR(x2, R[2][0]);
        t4 = x4;
        t2 ^= x2;
        x2 = ROTR(x2, R[2][1] - R[2][0]);
        t3 = x3;
        t1 ^= x1;
        x3 = ROTR(x3, R[3][0]);
        x0 ^= x4;
        x4 = ROTR(x4, R[4][0]);
        t3 ^= x3;
        x2 ^= t2;
        x1 = ROTR(x1, R[1][1] - R[1][0]);
        t0 = x0;
        x2 = ~x2;
        x3 = ROTR(x3, R[3][1] - R[3][0]);
        t4 ^= x4;
        x4 = ROTR(x4, R[4][1] - R[4][0]);
        x3 ^= t3;
        x1 ^= t1;
        x0 = ROTR(x0, R[0][0]);
        x4 ^= t4;
        t0 ^= x0;
        x0 = ROTR(x0, R[0][1] - R[0][0]);
        x0 ^= t0;
    }

    private void P12()
    {
        ROUND(0xf0);
        ROUND(0xe1);
        ROUND(0xd2);
        ROUND(0xc3);
        ROUND(0xb4);
        ROUND(0xa5);
        ROUND(0x96);
        ROUND(0x87);
        ROUND(0x78);
        ROUND(0x69);
        ROUND(0x5a);
        ROUND(0x4b);
    }

    private void P6()
    {
        ROUND(0x96);
        ROUND(0x87);
        ROUND(0x78);
        ROUND(0x69);
        ROUND(0x5a);
        ROUND(0x4b);
    }

    private void P1()
    {
        ROUND(0x4b);
    }

    private void rounds20X(short[] SX, short[] E)
    {
        short[] C = new short[5];
        C[0] = (short)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
        C[1] = (short)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
        C[2] = (short)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
        C[3] = (short)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
        C[4] = (short)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
        thetaRhoPiChiIotaPrepareTheta(0, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(1, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(2, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(3, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(4, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(5, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(6, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(7, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(8, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(9, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(10, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(11, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(12, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(13, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(14, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(15, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(16, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(17, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(18, SX, E, C);
        thetaRhoPiChiIota(19, E, SX, C);
    }


    private void rounds16X(short[] SX, short[] E)
    {
        short[] C = new short[5];
        C[0] = (short)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
        C[1] = (short)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
        C[2] = (short)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
        C[3] = (short)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
        C[4] = (short)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
        thetaRhoPiChiIotaPrepareTheta(4, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(5, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(6, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(7, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(8, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(9, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(10, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(11, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(12, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(13, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(14, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(15, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(16, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(17, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(18, SX, E, C);
        thetaRhoPiChiIota(19, E, SX, C);
    }

    private void rounds12X(short[] SX, short[] E)
    {
        short[] C = new short[5];
        C[0] = (short)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
        C[1] = (short)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
        C[2] = (short)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
        C[3] = (short)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
        C[4] = (short)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
        thetaRhoPiChiIotaPrepareTheta(8, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(9, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(10, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(11, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(12, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(13, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(14, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(15, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(16, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(17, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(18, SX, E, C);
        thetaRhoPiChiIota(19, E, SX, C);
    }

    private void rounds8X(short[] SX, short[] E)
    {
        short[] C = new short[5];
        C[0] = (short)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
        C[1] = (short)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
        C[2] = (short)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
        C[3] = (short)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
        C[4] = (short)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
        thetaRhoPiChiIotaPrepareTheta(12, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(13, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(14, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(15, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(16, SX, E, C);
        thetaRhoPiChiIotaPrepareTheta(17, E, SX, C);
        thetaRhoPiChiIotaPrepareTheta(18, SX, E, C);
        thetaRhoPiChiIota(19, E, SX, C);
    }

    private void rounds1X(short[] SX, short[] E)
    {
        short[] C = new short[5];
        C[0] = (short)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
        C[1] = (short)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
        C[2] = (short)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
        C[3] = (short)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
        C[4] = (short)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
        thetaRhoPiChiIotaPrepareTheta(19, SX, E, C);
        System.arraycopy(E, 0, SX, 0, E.length);
    }


    private void thetaRhoPiChiIotaPrepareTheta(int i, short[] A, short[] E, short[] C)
    {
        short Da = (short)(C[4] ^ ROL16(C[1], 1));
        short De = (short)(C[0] ^ ROL16(C[2], 1));
        short Di = (short)(C[1] ^ ROL16(C[3], 1));
        short Do = (short)(C[2] ^ ROL16(C[4], 1));
        short Du = (short)(C[3] ^ ROL16(C[0], 1));

        A[0] ^= Da;
        short Bba = A[0];
        A[6] ^= De;
        short Bbe = ROL16(A[6], 12);
        A[12] ^= Di;
        short Bbi = ROL16(A[12], 11);
        A[18] ^= Do;
        short Bbo = ROL16(A[18], 5);
        A[24] ^= Du;
        short Bbu = ROL16(A[24], 14);
        E[0] = (short)(Bba ^ ((~Bbe) & Bbi));
        E[0] ^= KeccakF400RoundConstants[i];
        C[0] = E[0];
        E[1] = (short)(Bbe ^ ((~Bbi) & Bbo));
        C[1] = E[1];
        E[2] = (short)(Bbi ^ ((~Bbo) & Bbu));
        C[2] = E[2];
        E[3] = (short)(Bbo ^ ((~Bbu) & Bba));
        C[3] = E[3];
        E[4] = (short)(Bbu ^ ((~Bba) & Bbe));
        C[4] = E[4];

        A[3] ^= Do;
        short Bga = ROL16(A[3], 12);
        A[9] ^= Du;
        short Bge = ROL16(A[9], 4);
        A[10] ^= Da;
        short Bgi = ROL16(A[10], 3);
        A[16] ^= De;
        short Bgo = ROL16(A[16], 13);
        A[22] ^= Di;
        short Bgu = ROL16(A[22], 13);
        E[5] = (short)(Bga ^ ((~Bge) & Bgi));
        C[0] ^= E[5];
        E[6] = (short)(Bge ^ ((~Bgi) & Bgo));
        C[1] ^= E[6];
        E[7] = (short)(Bgi ^ ((~Bgo) & Bgu));
        C[2] ^= E[7];
        E[8] = (short)(Bgo ^ ((~Bgu) & Bga));
        C[3] ^= E[8];
        E[9] = (short)(Bgu ^ ((~Bga) & Bge));
        C[4] ^= E[9];

        A[1] ^= De;
        short Bka = ROL16(A[1], 1);
        A[7] ^= Di;
        short Bke = ROL16(A[7], 6);
        A[13] ^= Do;
        short Bki = ROL16(A[13], 9);
        A[19] ^= Du;
        short Bko = ROL16(A[19], 8);
        A[20] ^= Da;
        short Bku = ROL16(A[20], 2);
        E[10] = (short)(Bka ^ ((~Bke) & Bki));
        C[0] ^= E[10];
        E[11] = (short)(Bke ^ ((~Bki) & Bko));
        C[1] ^= E[11];
        E[12] = (short)(Bki ^ ((~Bko) & Bku));
        C[2] ^= E[12];
        E[13] = (short)(Bko ^ ((~Bku) & Bka));
        C[3] ^= E[13];
        E[14] = (short)(Bku ^ ((~Bka) & Bke));
        C[4] ^= E[14];

        A[4] ^= Du;
        short Bma = ROL16(A[4], 11);
        A[5] ^= Da;
        short Bme = ROL16(A[5], 4);
        A[11] ^= De;
        short Bmi = ROL16(A[11], 10);
        A[17] ^= Di;
        short Bmo = ROL16(A[17], 15);
        A[23] ^= Do;
        short Bmu = ROL16(A[23], 8);
        E[15] = (short)(Bma ^ ((~Bme) & Bmi));
        C[0] ^= E[15];
        E[16] = (short)(Bme ^ ((~Bmi) & Bmo));
        C[1] ^= E[16];
        E[17] = (short)(Bmi ^ ((~Bmo) & Bmu));
        C[2] ^= E[17];
        E[18] = (short)(Bmo ^ ((~Bmu) & Bma));
        C[3] ^= E[18];
        E[19] = (short)(Bmu ^ ((~Bma) & Bme));
        C[4] ^= E[19];

        A[2] ^= Di;
        short Bsa = ROL16(A[2], 14);
        A[8] ^= Do;
        short Bse = ROL16(A[8], 7);
        A[14] ^= Du;
        short Bsi = ROL16(A[14], 7);
        A[15] ^= Da;
        short Bso = ROL16(A[15], 9);
        A[21] ^= De;
        short Bsu = ROL16(A[21], 2);
        E[20] = (short)(Bsa ^ ((~Bse) & Bsi));
        C[0] ^= E[20];
        E[21] = (short)(Bse ^ ((~Bsi) & Bso));
        C[1] ^= E[21];
        E[22] = (short)(Bsi ^ ((~Bso) & Bsu));
        C[2] ^= E[22];
        E[23] = (short)(Bso ^ ((~Bsu) & Bsa));
        C[3] ^= E[23];
        E[24] = (short)(Bsu ^ ((~Bsa) & Bse));
        C[4] ^= E[24];
    }

    private void thetaRhoPiChiIota(int i, short[] A, short[] E, short[] C)
    {
        short Da = (short)(C[4] ^ ROL16(C[1], 1));
        short De = (short)(C[0] ^ ROL16(C[2], 1));
        short Di = (short)(C[1] ^ ROL16(C[3], 1));
        short Do = (short)(C[2] ^ ROL16(C[4], 1));
        short Du = (short)(C[3] ^ ROL16(C[0], 1));

        A[0] ^= Da;
        short Bba = A[0];
        A[6] ^= De;
        short Bbe = ROL16(A[6], 12);
        A[12] ^= Di;
        short Bbi = ROL16(A[12], 11);
        A[18] ^= Do;
        short Bbo = ROL16(A[18], 5);
        A[24] ^= Du;
        short Bbu = ROL16(A[24], 14);
        E[0] = (short)(Bba ^ ((~Bbe) & Bbi));
        E[0] ^= KeccakF400RoundConstants[i];
        E[1] = (short)(Bbe ^ ((~Bbi) & Bbo));
        E[2] = (short)(Bbi ^ ((~Bbo) & Bbu));
        E[3] = (short)(Bbo ^ ((~Bbu) & Bba));
        E[4] = (short)(Bbu ^ ((~Bba) & Bbe));

        A[3] ^= Do;
        short Bga = ROL16(A[3], 12);
        A[9] ^= Du;
        short Bge = ROL16(A[9], 4);
        A[10] ^= Da;
        short Bgi = ROL16(A[10], 3);
        A[16] ^= De;
        short Bgo = ROL16(A[16], 13);
        A[22] ^= Di;
        short Bgu = ROL16(A[22], 13);
        E[5] = (short)(Bga ^ ((~Bge) & Bgi));
        E[6] = (short)(Bge ^ ((~Bgi) & Bgo));
        E[7] = (short)(Bgi ^ ((~Bgo) & Bgu));
        E[8] = (short)(Bgo ^ ((~Bgu) & Bga));
        E[9] = (short)(Bgu ^ ((~Bga) & Bge));

        A[1] ^= De;
        short Bka = ROL16(A[1], 1);
        A[7] ^= Di;
        short Bke = ROL16(A[7], 6);
        A[13] ^= Do;
        short Bki = ROL16(A[13], 9);
        A[19] ^= Du;
        short Bko = ROL16(A[19], 8);
        A[20] ^= Da;
        short Bku = ROL16(A[20], 2);
        E[10] = (short)(Bka ^ ((~Bke) & Bki));
        E[11] = (short)(Bke ^ ((~Bki) & Bko));
        E[12] = (short)(Bki ^ ((~Bko) & Bku));
        E[13] = (short)(Bko ^ ((~Bku) & Bka));
        E[14] = (short)(Bku ^ ((~Bka) & Bke));

        A[4] ^= Du;
        short Bma = ROL16(A[4], 11);
        A[5] ^= Da;
        short Bme = ROL16(A[5], 4);
        A[11] ^= De;
        short Bmi = ROL16(A[11], 10);
        A[17] ^= Di;
        short Bmo = ROL16(A[17], 15);
        A[23] ^= Do;
        short Bmu = ROL16(A[23], 8);
        E[15] = (short)(Bma ^ ((~Bme) & Bmi));
        E[16] = (short)(Bme ^ ((~Bmi) & Bmo));
        E[17] = (short)(Bmi ^ ((~Bmo) & Bmu));
        E[18] = (short)(Bmo ^ ((~Bmu) & Bma));
        E[19] = (short)(Bmu ^ ((~Bma) & Bme));

        A[2] ^= Di;
        short Bsa = ROL16(A[2], 14);
        A[8] ^= Do;
        short Bse = ROL16(A[8], 7);
        A[14] ^= Du;
        short Bsi = ROL16(A[14], 7);
        A[15] ^= Da;
        short Bso = ROL16(A[15], 9);
        A[21] ^= De;
        short Bsu = ROL16(A[21], 2);
        E[20] = (short)(Bsa ^ ((~Bse) & Bsi));
        E[21] = (short)(Bse ^ ((~Bsi) & Bso));
        E[22] = (short)(Bsi ^ ((~Bso) & Bsu));
        E[23] = (short)(Bso ^ ((~Bsu) & Bsa));
        E[24] = (short)(Bsu ^ ((~Bsa) & Bse));
    }

}
