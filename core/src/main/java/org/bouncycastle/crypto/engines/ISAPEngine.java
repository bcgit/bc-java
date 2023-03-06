package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

/**
 * ISAP AEAD v2, https://isap.iaik.tugraz.at/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
 * <p>
 * ISAP AEAD v2 with reference to C Reference Impl from: https://github.com/isap-lwc/isap-code-package
 * </p>
 */

public class ISAPEngine
    implements AEADCipher
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
            ISAPAEAD = new ISAPAEAD_A_128A();
            algorithmName = "ISAP-A-128A AEAD";
            break;
        case ISAP_K_128A:
            ISAPAEAD = new ISAPAEAD_K_128A();
            algorithmName = "ISAP-K-128A AEAD";
            break;
        case ISAP_A_128:
            ISAPAEAD = new ISAPAEAD_A_128();
            algorithmName = "ISAP-A-128 AEAD";
            break;
        case ISAP_K_128:
            ISAPAEAD = new ISAPAEAD_K_128();
            algorithmName = "ISAP-K-128 AEAD";
            break;
        }
    }

    private String algorithmName;
    private boolean forEncryption;
    private boolean initialised;
    final int CRYPTO_KEYBYTES = 16;
    final int CRYPTO_NPUBBYTES = 16;
    final int ISAP_STATE_SZ = 40;
    private byte[] k;
    private byte[] c;
    private byte[] ad;
    private byte[] npub;
    private byte[] mac;
    private ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private int ISAP_rH;
    private int ISAP_rH_SZ;
    private ISAP_AEAD ISAPAEAD;

    private interface ISAP_AEAD
    {
        void isap_enc(byte[] m, int mOff, int mlen, byte[] c, int cOff, int clen);

        void init();

        void isap_mac(byte[] ad, int adlen, byte[] c, int clen, byte[] tag, int tagOff);

        void reset();
    }

    public abstract class ISAPAEAD_A
        implements ISAP_AEAD
    {
        protected long[] k64;
        protected long[] npub64;
        protected long ISAP_IV1_64;
        protected long ISAP_IV2_64;
        protected long ISAP_IV3_64;
        protected long x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;

        public ISAPAEAD_A()
        {
            ISAP_rH = 64;
            ISAP_rH_SZ = (ISAP_rH + 7) >> 3;
        }

        public void init()
        {
            npub64 = new long[getLongSize(npub.length)];
            Pack.littleEndianToLong(npub, 0, npub64, 0, npub64.length);
            npub64[0] = U64BIG(npub64[0]);
            npub64[1] = U64BIG(npub64[1]);
            k64 = new long[getLongSize(k.length)];
            Pack.littleEndianToLong(k, 0, k64, 0, k64.length);
            k64[0] = U64BIG(k64[0]);
            k64[1] = U64BIG(k64[1]);
            reset();
        }

        protected abstract void PX1();

        protected abstract void PX2();

        protected void ABSORB_MAC(byte[] src, int len)
        {
            long[] src64 = new long[src.length >> 3];
            Pack.littleEndianToLong(src, 0, src64, 0, src64.length);
            int idx = 0;
            while (len >= ISAP_rH_SZ)
            {
                x0 ^= U64BIG(src64[idx++]);
                P12();
                len -= ISAP_rH_SZ;
            }
            /* Absorb final ad block */
            for (int i = 0; i < len; ++i)
            {
                x0 ^= (src[(idx << 3) + i] & 0xFFL) << ((7 - i) << 3);
            }
            x0 ^= 0x80L << ((7 - len) << 3);
            P12();
        }

        public void isap_mac(byte[] ad, int adlen, byte[] c, int clen, byte[] tag, int tagOff)
        {
            // Init State
            x0 = npub64[0];
            x1 = npub64[1];
            x2 = ISAP_IV1_64;
            x3 = x4 = 0;
            P12();
            ABSORB_MAC(ad, adlen);
            // Domain seperation
            x4 ^= 1L;
            ABSORB_MAC(c, clen);
            // Derive K*
            Pack.longToLittleEndian(U64BIG(x0), tag, 0);
            Pack.longToLittleEndian(U64BIG(x1), tag, 8);
            long tmp_x2 = x2, tmp_x3 = x3, tmp_x4 = x4;
            isap_rk(ISAP_IV2_64, tag, CRYPTO_KEYBYTES);
            x2 = tmp_x2;
            x3 = tmp_x3;
            x4 = tmp_x4;
            // Squeeze tag
            P12();
            Pack.longToLittleEndian(U64BIG(x0), tag, tagOff);
            Pack.longToLittleEndian(U64BIG(x1), tag, tagOff + 8);
        }

        public void isap_rk(long iv64, byte[] y, int ylen)
        {
            // Init state
            x0 = k64[0];
            x1 = k64[1];
            x2 = iv64;
            x3 = x4 = 0;
            P12();
            // Absorb Y
            for (int i = 0; i < (ylen << 3) - 1; i++)
            {
                x0 ^= ((((y[i >>> 3] >>> (7 - (i & 7))) & 0x01) << 7) & 0xFFL) << 56;
                PX2();
            }
            x0 ^= (((y[ylen - 1]) & 0x01L) << 7) << 56;
            P12();
        }

        public void isap_enc(byte[] m, int mOff, int mlen, byte[] c, int cOff, int clen)
        {
            /* Encrypt m */
            long[] m64 = new long[mlen >> 3];
            Pack.littleEndianToLong(m, mOff, m64, 0, m64.length);
            long[] c64 = new long[m64.length];
            int idx = 0;
            while (mlen >= ISAP_rH_SZ)
            {
                c64[idx] = U64BIG(x0) ^ m64[idx];
                PX1();
                idx++;
                mlen -= ISAP_rH_SZ;
            }
            Pack.longToLittleEndian(c64, 0, c64.length, c, cOff);
            /* Encrypt final m block */
            byte[] xo = Pack.longToLittleEndian(x0);
            while (mlen > 0)
            {
                c[(idx << 3) + cOff + mlen - 1] = (byte)(xo[ISAP_rH_SZ - mlen] ^ m[(idx << 3) + mOff + --mlen]);
            }
        }

        public void reset()
        {
            // Init state
            isap_rk(ISAP_IV3_64, npub, CRYPTO_NPUBBYTES);
            x3 = npub64[0];
            x4 = npub64[1];
            PX1();
        }

        private int getLongSize(int x)
        {
            return (x >>> 3) + ((x & 7) != 0 ? 1 : 0);
        }

        private long ROTR(long x, long n)
        {
            return (x >>> n) | (x << (64 - n));
        }

        protected long U64BIG(long x)
        {
            return ((ROTR(x, 8) & (0xFF000000FF000000L)) | (ROTR(x, 24) & (0x00FF000000FF0000L)) |
                (ROTR(x, 40) & (0x0000FF000000FF00L)) | (ROTR(x, 56) & (0x000000FF000000FFL)));
        }

        protected void ROUND(long C)
        {
            t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
            t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
            t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
            t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
            t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ ROTR(t0, 19) ^ ROTR(t0, 28);
            x1 = t1 ^ ROTR(t1, 39) ^ ROTR(t1, 61);
            x2 = ~(t2 ^ ROTR(t2, 1) ^ ROTR(t2, 6));
            x3 = t3 ^ ROTR(t3, 10) ^ ROTR(t3, 17);
            x4 = t4 ^ ROTR(t4, 7) ^ ROTR(t4, 41);
        }

        public void P12()
        {
            ROUND(0xf0);
            ROUND(0xe1);
            ROUND(0xd2);
            ROUND(0xc3);
            ROUND(0xb4);
            ROUND(0xa5);
            P6();
        }

        protected void P6()
        {
            ROUND(0x96);
            ROUND(0x87);
            ROUND(0x78);
            ROUND(0x69);
            ROUND(0x5a);
            ROUND(0x4b);
        }
    }

    private class ISAPAEAD_A_128A
        extends ISAPAEAD_A
    {
        public ISAPAEAD_A_128A()
        {
            ISAP_IV1_64 = 108156764297430540L;
            ISAP_IV2_64 = 180214358335358476L;
            ISAP_IV3_64 = 252271952373286412L;
        }

        protected void PX1()
        {
            P6();
        }

        protected void PX2()
        {
            ROUND(0x4b);
        }
    }

    private class ISAPAEAD_A_128
        extends ISAPAEAD_A
    {
        public ISAPAEAD_A_128()
        {
            ISAP_IV1_64 = 108156764298152972L;
            ISAP_IV2_64 = 180214358336080908L;
            ISAP_IV3_64 = 252271952374008844L;
        }

        protected void PX1()
        {
            P12();
        }

        protected void PX2()
        {
            P12();
        }
    }

    private abstract class ISAPAEAD_K
        implements ISAP_AEAD
    {
        final int ISAP_STATE_SZ_CRYPTO_NPUBBYTES = ISAP_STATE_SZ - CRYPTO_NPUBBYTES;
        protected short[] ISAP_IV1_16;
        protected short[] ISAP_IV2_16;
        protected short[] ISAP_IV3_16;
        protected short[] k16;
        protected short[] iv16;
        private final int[] KeccakF400RoundConstants = {0x0001, 0x8082, 0x808a, 0x8000, 0x808b, 0x0001, 0x8081, 0x8009,
            0x008a, 0x0088, 0x8009, 0x000a, 0x808b, 0x008b, 0x8089, 0x8003, 0x8002, 0x0080, 0x800a, 0x000a};
        protected short[] SX = new short[25];
        protected short[] E = new short[25];
        protected short[] C = new short[5];

        public ISAPAEAD_K()
        {
            ISAP_rH = 144;
            ISAP_rH_SZ = (ISAP_rH + 7) >> 3;
        }

        public void init()
        {
            k16 = new short[k.length >> 1];
            byteToShort(k, k16, k16.length);
            iv16 = new short[npub.length >> 1];
            byteToShort(npub, iv16, iv16.length);
            reset();
        }

        public void reset()
        {
            // Init state
            SX = new short[25];
            E = new short[25];
            C = new short[5];
            isap_rk(ISAP_IV3_16, npub, CRYPTO_NPUBBYTES, SX, ISAP_STATE_SZ_CRYPTO_NPUBBYTES, C);
            System.arraycopy(iv16, 0, SX, 17, 8);
            PermuteRoundsKX(SX, E, C);
        }

        protected abstract void PermuteRoundsHX(short[] SX, short[] E, short[] C);

        protected abstract void PermuteRoundsKX(short[] SX, short[] E, short[] C);

        protected abstract void PermuteRoundsBX(short[] SX, short[] E, short[] C);

        protected void ABSORB_MAC(short[] SX, byte[] src, int len, short[] E, short[] C)
        {
            int rem_bytes = len;
            int idx = 0;
            while (true)
            {
                if (rem_bytes > ISAP_rH_SZ)
                {
                    byteToShortXor(src, SX, ISAP_rH_SZ >> 1);
                    idx += ISAP_rH_SZ;
                    rem_bytes -= ISAP_rH_SZ;
                    PermuteRoundsHX(SX, E, C);
                }
                else if (rem_bytes == ISAP_rH_SZ)
                {
                    byteToShortXor(src, SX, ISAP_rH_SZ >> 1);
                    PermuteRoundsHX(SX, E, C);
                    SX[0] ^= 0x80;
                    PermuteRoundsHX(SX, E, C);
                    break;
                }
                else
                {
                    for (int i = 0; i < rem_bytes; i++)
                    {
                        SX[i >> 1] ^= (src[idx++] & 0xFF) << ((i & 1) << 3);
                    }
                    SX[rem_bytes >> 1] ^= 0x80 << ((rem_bytes & 1) << 3);
                    PermuteRoundsHX(SX, E, C);
                    break;
                }
            }
        }

        public void isap_rk(short[] iv16, byte[] y, int ylen, short[] out16, int outlen, short[] C)
        {
            // Init state
            short[] SX = new short[25];
            short[] E = new short[25];
            System.arraycopy(k16, 0, SX, 0, 8);
            System.arraycopy(iv16, 0, SX, 8, 4);
            PermuteRoundsKX(SX, E, C);
            // Absorb all bits of Y
            for (int i = 0; i < (ylen << 3) - 1; i++)
            {
                SX[0] ^= (((y[i >> 3] >>> (7 - (i & 7))) & 0x01) << 7);
                PermuteRoundsBX(SX, E, C);
            }
            SX[0] ^= (((y[ylen - 1]) & 0x01) << 7);
            PermuteRoundsKX(SX, E, C);
            // Extract K*
            System.arraycopy(SX, 0, out16, 0, outlen == ISAP_STATE_SZ_CRYPTO_NPUBBYTES ? 17 : 8);
        }

        public void isap_mac(byte[] ad, int adlen, byte[] c, int clen, byte[] tag, int tagOff)
        {
            SX = new short[25];
            // Init state
            System.arraycopy(iv16, 0, SX, 0, 8);
            System.arraycopy(ISAP_IV1_16, 0, SX, 8, 4);
            PermuteRoundsHX(SX, E, C);
            // Absorb AD
            ABSORB_MAC(SX, ad, adlen, E, C);
            // Domain seperation
            SX[24] ^= 0x0100;
            // Absorb C
            ABSORB_MAC(SX, c, clen, E, C);
            // Derive K*
            shortToByte(SX, tag, tagOff);
            isap_rk(ISAP_IV2_16, tag, CRYPTO_KEYBYTES, SX, CRYPTO_KEYBYTES, C);
            // Squeeze tag
            PermuteRoundsHX(SX, E, C);
            shortToByte(SX, tag, tagOff);
        }

        public void isap_enc(byte[] m, int mOff, int mlen, byte[] c, int cOff, int clen)
        {
            // Squeeze key stream
            while (true)
            {
                if (mlen >= ISAP_rH_SZ)
                {
                    // Squeeze full lane and continue
                    for (int i = 0; i < ISAP_rH_SZ; ++i)
                    {
                        c[cOff++] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[mOff++]);
                    }
                    mlen -= ISAP_rH_SZ;
                    PermuteRoundsKX(SX, E, C);
                }
                else
                {
                    // Squeeze full or partial lane and stop
                    for (int i = 0; i < mlen; ++i)
                    {
                        c[cOff++] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m[mOff++]);
                    }
                    break;
                }
            }
        }

        private void byteToShortXor(byte[] input, short[] output, int outLen)
        {
            for (int i = 0; i < outLen; ++i)
            {
                output[i] ^= Pack.littleEndianToShort(input, (i << 1));
            }
        }

        private void byteToShort(byte[] input, short[] output, int outLen)
        {
            for (int i = 0; i < outLen; ++i)
            {
                output[i] = Pack.littleEndianToShort(input, (i << 1));
            }
        }

        private void shortToByte(short[] input, byte[] output, int outOff)
        {
            for (int i = 0; i < 8; ++i)
            {
                Pack.shortToLittleEndian(input[i], output, outOff + (i << 1));
            }
        }

        protected void rounds12X(short[] SX, short[] E, short[] C)
        {
            prepareThetaX(SX, C);
            rounds_8_18(SX, E, C);
        }

        protected void rounds_4_18(short[] SX, short[] E, short[] C)
        {
            thetaRhoPiChiIotaPrepareTheta(4, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(5, E, SX, C);
            thetaRhoPiChiIotaPrepareTheta(6, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(7, E, SX, C);
            rounds_8_18(SX, E, C);
        }

        protected void rounds_8_18(short[] SX, short[] E, short[] C)
        {
            thetaRhoPiChiIotaPrepareTheta(8, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(9, E, SX, C);
            thetaRhoPiChiIotaPrepareTheta(10, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(11, E, SX, C);
            rounds_12_18(SX, E, C);
        }

        protected void rounds_12_18(short[] SX, short[] E, short[] C)
        {
            thetaRhoPiChiIotaPrepareTheta(12, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(13, E, SX, C);
            thetaRhoPiChiIotaPrepareTheta(14, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(15, E, SX, C);
            thetaRhoPiChiIotaPrepareTheta(16, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(17, E, SX, C);
            thetaRhoPiChiIotaPrepareTheta(18, SX, E, C);
            thetaRhoPiChiIota(E, SX, C);
        }

        protected void prepareThetaX(short[] SX, short[] C)
        {
            C[0] = (short)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
            C[1] = (short)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
            C[2] = (short)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
            C[3] = (short)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
            C[4] = (short)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
        }

        private short ROL16(short a, int offset)
        {
            return (short)(((a & 0xFFFF) << offset) ^ ((a & 0xFFFF) >>> (16 - offset)));
        }

        protected void thetaRhoPiChiIotaPrepareTheta(int i, short[] A, short[] E, short[] C)
        {
            short Da = (short)(C[4] ^ ROL16(C[1], 1));
            short De = (short)(C[0] ^ ROL16(C[2], 1));
            short Di = (short)(C[1] ^ ROL16(C[3], 1));
            short Do = (short)(C[2] ^ ROL16(C[4], 1));
            short Du = (short)(C[3] ^ ROL16(C[0], 1));

            short Ba = A[0] ^= Da;
            A[6] ^= De;
            short Be = ROL16(A[6], 12);
            A[12] ^= Di;
            short Bi = ROL16(A[12], 11);
            A[18] ^= Do;
            short Bo = ROL16(A[18], 5);
            A[24] ^= Du;
            short Bu = ROL16(A[24], 14);
            C[0] = E[0] = (short)(Ba ^ ((~Be) & Bi) ^ KeccakF400RoundConstants[i]);
            C[1] = E[1] = (short)(Be ^ ((~Bi) & Bo));
            C[2] = E[2] = (short)(Bi ^ ((~Bo) & Bu));
            C[3] = E[3] = (short)(Bo ^ ((~Bu) & Ba));
            C[4] = E[4] = (short)(Bu ^ ((~Ba) & Be));

            A[3] ^= Do;
            Ba = ROL16(A[3], 12);
            A[9] ^= Du;
            Be = ROL16(A[9], 4);
            A[10] ^= Da;
            Bi = ROL16(A[10], 3);
            A[16] ^= De;
            Bo = ROL16(A[16], 13);
            A[22] ^= Di;
            Bu = ROL16(A[22], 13);
            E[5] = (short)(Ba ^ ((~Be) & Bi));
            C[0] ^= E[5];
            E[6] = (short)(Be ^ ((~Bi) & Bo));
            C[1] ^= E[6];
            E[7] = (short)(Bi ^ ((~Bo) & Bu));
            C[2] ^= E[7];
            E[8] = (short)(Bo ^ ((~Bu) & Ba));
            C[3] ^= E[8];
            E[9] = (short)(Bu ^ ((~Ba) & Be));
            C[4] ^= E[9];

            A[1] ^= De;
            Ba = ROL16(A[1], 1);
            A[7] ^= Di;
            Be = ROL16(A[7], 6);
            A[13] ^= Do;
            Bi = ROL16(A[13], 9);
            A[19] ^= Du;
            Bo = ROL16(A[19], 8);
            A[20] ^= Da;
            Bu = ROL16(A[20], 2);
            E[10] = (short)(Ba ^ ((~Be) & Bi));
            C[0] ^= E[10];
            E[11] = (short)(Be ^ ((~Bi) & Bo));
            C[1] ^= E[11];
            E[12] = (short)(Bi ^ ((~Bo) & Bu));
            C[2] ^= E[12];
            E[13] = (short)(Bo ^ ((~Bu) & Ba));
            C[3] ^= E[13];
            E[14] = (short)(Bu ^ ((~Ba) & Be));
            C[4] ^= E[14];

            A[4] ^= Du;
            Ba = ROL16(A[4], 11);
            A[5] ^= Da;
            Be = ROL16(A[5], 4);
            A[11] ^= De;
            Bi = ROL16(A[11], 10);
            A[17] ^= Di;
            Bo = ROL16(A[17], 15);
            A[23] ^= Do;
            Bu = ROL16(A[23], 8);
            E[15] = (short)(Ba ^ ((~Be) & Bi));
            C[0] ^= E[15];
            E[16] = (short)(Be ^ ((~Bi) & Bo));
            C[1] ^= E[16];
            E[17] = (short)(Bi ^ ((~Bo) & Bu));
            C[2] ^= E[17];
            E[18] = (short)(Bo ^ ((~Bu) & Ba));
            C[3] ^= E[18];
            E[19] = (short)(Bu ^ ((~Ba) & Be));
            C[4] ^= E[19];

            A[2] ^= Di;
            Ba = ROL16(A[2], 14);
            A[8] ^= Do;
            Be = ROL16(A[8], 7);
            A[14] ^= Du;
            Bi = ROL16(A[14], 7);
            A[15] ^= Da;
            Bo = ROL16(A[15], 9);
            A[21] ^= De;
            Bu = ROL16(A[21], 2);
            E[20] = (short)(Ba ^ ((~Be) & Bi));
            C[0] ^= E[20];
            E[21] = (short)(Be ^ ((~Bi) & Bo));
            C[1] ^= E[21];
            E[22] = (short)(Bi ^ ((~Bo) & Bu));
            C[2] ^= E[22];
            E[23] = (short)(Bo ^ ((~Bu) & Ba));
            C[3] ^= E[23];
            E[24] = (short)(Bu ^ ((~Ba) & Be));
            C[4] ^= E[24];
        }

        protected void thetaRhoPiChiIota(short[] A, short[] E, short[] C)
        {
            short Da = (short)(C[4] ^ ROL16(C[1], 1));
            short De = (short)(C[0] ^ ROL16(C[2], 1));
            short Di = (short)(C[1] ^ ROL16(C[3], 1));
            short Do = (short)(C[2] ^ ROL16(C[4], 1));
            short Du = (short)(C[3] ^ ROL16(C[0], 1));

            short Ba = A[0] ^= Da;
            A[6] ^= De;
            short Be = ROL16(A[6], 12);
            A[12] ^= Di;
            short Bi = ROL16(A[12], 11);
            A[18] ^= Do;
            short Bo = ROL16(A[18], 5);
            A[24] ^= Du;
            short Bu = ROL16(A[24], 14);
            E[0] = (short)(Ba ^ ((~Be) & Bi) ^ KeccakF400RoundConstants[19]);
            E[1] = (short)(Be ^ ((~Bi) & Bo));
            E[2] = (short)(Bi ^ ((~Bo) & Bu));
            E[3] = (short)(Bo ^ ((~Bu) & Ba));
            E[4] = (short)(Bu ^ ((~Ba) & Be));

            A[3] ^= Do;
            Ba = ROL16(A[3], 12);
            A[9] ^= Du;
            Be = ROL16(A[9], 4);
            A[10] ^= Da;
            Bi = ROL16(A[10], 3);
            A[16] ^= De;
            Bo = ROL16(A[16], 13);
            A[22] ^= Di;
            Bu = ROL16(A[22], 13);
            E[5] = (short)(Ba ^ ((~Be) & Bi));
            E[6] = (short)(Be ^ ((~Bi) & Bo));
            E[7] = (short)(Bi ^ ((~Bo) & Bu));
            E[8] = (short)(Bo ^ ((~Bu) & Ba));
            E[9] = (short)(Bu ^ ((~Ba) & Be));

            A[1] ^= De;
            Ba = ROL16(A[1], 1);
            A[7] ^= Di;
            Be = ROL16(A[7], 6);
            A[13] ^= Do;
            Bi = ROL16(A[13], 9);
            A[19] ^= Du;
            Bo = ROL16(A[19], 8);
            A[20] ^= Da;
            Bu = ROL16(A[20], 2);
            E[10] = (short)(Ba ^ ((~Be) & Bi));
            E[11] = (short)(Be ^ ((~Bi) & Bo));
            E[12] = (short)(Bi ^ ((~Bo) & Bu));
            E[13] = (short)(Bo ^ ((~Bu) & Ba));
            E[14] = (short)(Bu ^ ((~Ba) & Be));

            A[4] ^= Du;
            Ba = ROL16(A[4], 11);
            A[5] ^= Da;
            Be = ROL16(A[5], 4);
            A[11] ^= De;
            Bi = ROL16(A[11], 10);
            A[17] ^= Di;
            Bo = ROL16(A[17], 15);
            A[23] ^= Do;
            Bu = ROL16(A[23], 8);
            E[15] = (short)(Ba ^ ((~Be) & Bi));
            E[16] = (short)(Be ^ ((~Bi) & Bo));
            E[17] = (short)(Bi ^ ((~Bo) & Bu));
            E[18] = (short)(Bo ^ ((~Bu) & Ba));
            E[19] = (short)(Bu ^ ((~Ba) & Be));

            A[2] ^= Di;
            Ba = ROL16(A[2], 14);
            A[8] ^= Do;
            Be = ROL16(A[8], 7);
            A[14] ^= Du;
            Bi = ROL16(A[14], 7);
            A[15] ^= Da;
            Bo = ROL16(A[15], 9);
            A[21] ^= De;
            Bu = ROL16(A[21], 2);
            E[20] = (short)(Ba ^ ((~Be) & Bi));
            E[21] = (short)(Be ^ ((~Bi) & Bo));
            E[22] = (short)(Bi ^ ((~Bo) & Bu));
            E[23] = (short)(Bo ^ ((~Bu) & Ba));
            E[24] = (short)(Bu ^ ((~Ba) & Be));
        }
    }

    private class ISAPAEAD_K_128A
        extends ISAPAEAD_K
    {
        public ISAPAEAD_K_128A()
        {
            ISAP_IV1_16 = new short[]{-32767, 400, 272, 2056};
            ISAP_IV2_16 = new short[]{-32766, 400, 272, 2056};
            ISAP_IV3_16 = new short[]{-32765, 400, 272, 2056};
        }

        protected void PermuteRoundsHX(short[] SX, short[] E, short[] C)
        {
            prepareThetaX(SX, C);
            rounds_4_18(SX, E, C);
        }

        protected void PermuteRoundsKX(short[] SX, short[] E, short[] C)
        {
            prepareThetaX(SX, C);
            rounds_12_18(SX, E, C);
        }

        protected void PermuteRoundsBX(short[] SX, short[] E, short[] C)
        {
            prepareThetaX(SX, C);
            thetaRhoPiChiIotaPrepareTheta(19, SX, E, C);
            System.arraycopy(E, 0, SX, 0, E.length);
        }
    }

    private class ISAPAEAD_K_128
        extends ISAPAEAD_K
    {
        public ISAPAEAD_K_128()
        {
            ISAP_IV1_16 = new short[]{-32767, 400, 3092, 3084};
            ISAP_IV2_16 = new short[]{-32766, 400, 3092, 3084};
            ISAP_IV3_16 = new short[]{-32765, 400, 3092, 3084};
        }

        protected void PermuteRoundsHX(short[] SX, short[] E, short[] C)
        {
            prepareThetaX(SX, C);
            thetaRhoPiChiIotaPrepareTheta(0, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(1, E, SX, C);
            thetaRhoPiChiIotaPrepareTheta(2, SX, E, C);
            thetaRhoPiChiIotaPrepareTheta(3, E, SX, C);
            rounds_4_18(SX, E, C);
        }

        protected void PermuteRoundsKX(short[] SX, short[] E, short[] C)
        {
            rounds12X(SX, E, C);
        }

        protected void PermuteRoundsBX(short[] SX, short[] E, short[] C)
        {
            rounds12X(SX, E, C);
        }
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException(
                "ISAP AEAD init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV)params;

        byte[] iv = ivParams.getIV();

        if (iv == null || iv.length != 16)
        {
            throw new IllegalArgumentException(
                "ISAP AEAD requires exactly 12 bytes of IV");
        }

        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "ISAP AEAD init parameters must include a key");
        }

        KeyParameter key = (KeyParameter)ivParams.getParameters();
        byte[] keyBytes = key.getKey();
        if (keyBytes.length != 16)
        {
            throw new IllegalArgumentException(
                "ISAP AEAD key must be 128 bits long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));

        /**
         * Initialize variables.
         */
        npub = new byte[iv.length];
        k = new byte[keyBytes.length];
        System.arraycopy(iv, 0, npub, 0, iv.length);
        System.arraycopy(keyBytes, 0, k, 0, keyBytes.length);
        ISAPAEAD.init();
        initialised = true;
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    @Override
    public void processAADByte(byte in)
    {
        aadData.write(in);
    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short" + (forEncryption ? "encryption" : "decryption"));
        }

        aadData.write(in, inOff, len);
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{in}, 0, 1, out, outOff);
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        message.write(input, inOff, len);
        if (forEncryption)
        {
            if (message.size() >= ISAP_rH_SZ)
            {
                len = message.size() / ISAP_rH_SZ * ISAP_rH_SZ;
                if (outOff + len > output.length)
                {
                    throw new OutputLengthException("output buffer is too short");
                }
                byte[] enc_input = message.toByteArray();
                ISAPAEAD.isap_enc(enc_input, 0, len, output, outOff, output.length);
                outputStream.write(output, outOff, len);
                message.reset();
                message.write(enc_input, len, enc_input.length - len);
                return len;
            }
        }
        return 0;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        int len;
        if (forEncryption)
        {
            byte[] enc_input = message.toByteArray();
            len = enc_input.length;
            if (outOff + len + 16 > output.length)
            {
                throw new OutputLengthException("output buffer is too short");
            }
            ISAPAEAD.isap_enc(enc_input, 0, len, output, outOff, output.length);
            outputStream.write(output, outOff, len);
            outOff += len;
            ad = aadData.toByteArray();
            c = outputStream.toByteArray();
            mac = new byte[16];
            ISAPAEAD.isap_mac(ad, ad.length, c, c.length, mac, 0);
            System.arraycopy(mac, 0, output, outOff, 16);
            len += 16;
        }
        else
        {
            ad = aadData.toByteArray();
            c = message.toByteArray();
            mac = new byte[16];
            len = c.length - mac.length;
            if (len + outOff > output.length)
            {
                throw new OutputLengthException("output buffer is too short");
            }
            ISAPAEAD.isap_mac(ad, ad.length, c, len, mac, 0);
            ISAPAEAD.reset();
            for (int i = 0; i < 16; ++i)
            {
                if (mac[i] != c[len + i])
                {
                    throw new IllegalArgumentException("Mac does not match");
                }
            }
            ISAPAEAD.isap_enc(c, 0, len, output, outOff, output.length);
        }
        return len;
    }

    @Override
    public byte[] getMac()
    {
        return mac;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    @Override
    public int getOutputSize(int len)
    {
        return len + 16;
    }

    @Override
    public void reset()
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        aadData.reset();
        ISAPAEAD.reset();
        message.reset();
        outputStream.reset();
    }

    public int getKeyBytesSize()
    {
        return CRYPTO_KEYBYTES;
    }

    public int getIVBytesSize()
    {
        return CRYPTO_NPUBBYTES;
    }

    public int getBlockSize()
    {
        return ISAP_rH_SZ;
    }
}
