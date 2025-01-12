package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * ISAP AEAD v2, https://isap.iaik.tugraz.at/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
 * <p>
 * ISAP AEAD v2 with reference to C Reference Impl from: https://github.com/isap-lwc/isap-code-package
 * </p>
 */
public class ISAPEngine
    extends AEADBufferBaseEngine
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
        KEY_SIZE = 16;
        IV_SIZE = 16;
        MAC_SIZE = 16;
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
        AADBufferSize = BlockSize;
        m_aad = new byte[AADBufferSize];
    }

    final int ISAP_STATE_SZ = 40;
    private byte[] k;
    private byte[] npub;
    private int ISAP_rH;
    private ISAP_AEAD ISAPAEAD;

    private interface ISAP_AEAD
    {
        void init();

        void reset();

        void absorbMacBlock(byte[] input, int inOff);

        void absorbFinalAADBlock();

        void swapInternalState();

        void processEncBlock(byte[] input, int inOff, byte[] output, int outOff);

        void processEncFinalBlock(byte[] output, int outOff);

        void processMACFinal(byte[] input, int inOff, int len, byte[] tag);
    }

    private abstract class ISAPAEAD_A
        implements ISAP_AEAD
    {
        protected long[] k64;
        protected long[] npub64;
        protected long ISAP_IV1_64;
        protected long ISAP_IV2_64;
        protected long ISAP_IV3_64;
        protected long x0, x1, x2, x3, x4, t0, t1, t2, t3, t4, macx0, macx1, macx2, macx3, macx4;

        public ISAPAEAD_A()
        {
            ISAP_rH = 64;
            BlockSize = (ISAP_rH + 7) >> 3;
        }

        public void init()
        {
            npub64 = new long[getLongSize(npub.length)];
            k64 = new long[getLongSize(k.length)];
            Pack.bigEndianToLong(npub, 0, npub64);
            Pack.bigEndianToLong(k, 0, k64);
            //reset();
        }

        protected abstract void PX1();

        protected abstract void PX2();

        public void swapInternalState()
        {
            t0 = x0;
            t1 = x1;
            t2 = x2;
            t3 = x3;
            t4 = x4;
            x0 = macx0;
            x1 = macx1;
            x2 = macx2;
            x3 = macx3;
            x4 = macx4;
            macx0 = t0;
            macx1 = t1;
            macx2 = t2;
            macx3 = t3;
            macx4 = t4;
        }

        public void absorbMacBlock(byte[] input, int inOff)
        {
            x0 ^= Pack.bigEndianToLong(input, inOff);
            P12();
        }

        public void absorbFinalAADBlock()
        {
            if (m_aadPos == AADBufferSize)
            {
                absorbMacBlock(m_aad, 0);
                m_aadPos = 0;
            }
            else
            {
                for (int i = 0; i < m_aadPos; ++i)
                {
                    x0 ^= (m_aad[i] & 0xFFL) << ((7 - i) << 3);
                }
            }
            x0 ^= 0x80L << ((7 - m_aadPos) << 3);
            P12();
            x4 ^= 1L;
        }

        public void processMACFinal(byte[] input, int inOff, int len, byte[] tag)
        {
            if (len == BlockSize)
            {
                absorbMacBlock(input, inOff);
                len = 0;
            }
            else
            {
                for (int i = 0; i < len; ++i)
                {
                    x0 ^= (input[inOff++] & 0xFFL) << ((7 - i) << 3);
                }
            }
            x0 ^= 0x80L << ((7 - len) << 3);
            P12();
            // Derive K*
            Pack.longToBigEndian(x0, tag, 0);
            Pack.longToBigEndian(x1, tag, 8);
            long tmp_x2 = x2, tmp_x3 = x3, tmp_x4 = x4;
            isap_rk(ISAP_IV2_64, tag, KEY_SIZE);
            x2 = tmp_x2;
            x3 = tmp_x3;
            x4 = tmp_x4;
            // Squeeze tag
            P12();
            Pack.longToBigEndian(x0, tag, 0);
            Pack.longToBigEndian(x1, tag, 8);
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

        public void processEncBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            long m64 = Pack.littleEndianToLong(input, inOff);
            long c64 = U64BIG(x0) ^ m64;
            PX1();
            Pack.longToLittleEndian(c64, output, outOff);
        }

        public void processEncFinalBlock(byte[] output, int outOff)
        {
            if (m_bufPos == BlockSize)
            {
                processEncBlock(m_buf, 0, output, outOff);
            }
            else
            {
                /* Encrypt final m block */
                byte[] xo = Pack.longToLittleEndian(x0);
                int mlen = m_bufPos;
                while (mlen > 0)
                {
                    output[outOff + mlen - 1] = (byte)(xo[BlockSize - mlen] ^ m_buf[--mlen]);
                }
            }
        }

        public void reset()
        {
            // Init state
            isap_rk(ISAP_IV3_64, npub, IV_SIZE);
            x3 = npub64[0];
            x4 = npub64[1];
            PX1();
            swapInternalState();
            // Init State for mac
            x0 = npub64[0];
            x1 = npub64[1];
            x2 = ISAP_IV1_64;
            x3 = x4 = 0;
            P12();
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
        final int ISAP_STATE_SZ_CRYPTO_NPUBBYTES = ISAP_STATE_SZ - IV_SIZE;
        protected short[] ISAP_IV1_16;
        protected short[] ISAP_IV2_16;
        protected short[] ISAP_IV3_16;
        protected short[] k16;
        protected short[] iv16;
        private final int[] KeccakF400RoundConstants = {0x0001, 0x8082, 0x808a, 0x8000, 0x808b, 0x0001, 0x8081, 0x8009,
            0x008a, 0x0088, 0x8009, 0x000a, 0x808b, 0x008b, 0x8089, 0x8003, 0x8002, 0x0080, 0x800a, 0x000a};
        protected short[] SX = new short[25];
        protected short[] macSX = new short[25];
        protected short[] E = new short[25];
        protected short[] C = new short[5];
        protected short[] macE = new short[25];
        protected short[] macC = new short[5];

        public ISAPAEAD_K()
        {
            ISAP_rH = 144;
            BlockSize = (ISAP_rH + 7) >> 3;
        }

        public void init()
        {
            k16 = new short[k.length >> 1];
            byteToShort(k, k16, k16.length);
            iv16 = new short[npub.length >> 1];
            byteToShort(npub, iv16, iv16.length);
            //reset();
        }

        public void reset()
        {
            // Init state
            Arrays.fill(SX, (byte)0);
            isap_rk(ISAP_IV3_16, npub, IV_SIZE, SX, ISAP_STATE_SZ_CRYPTO_NPUBBYTES, C);
            System.arraycopy(iv16, 0, SX, 17, 8);
            PermuteRoundsKX(SX, E, C);
            // Init state for mac
            swapInternalState();
            Arrays.fill(SX, 12, 25, (short)0);
            System.arraycopy(iv16, 0, SX, 0, 8);
            System.arraycopy(ISAP_IV1_16, 0, SX, 8, 4);
            PermuteRoundsHX(SX, E, C);
        }

        public void swapInternalState()
        {
            short[] tmp = SX;
            SX = macSX;
            macSX = tmp;
            tmp = E;
            E = macE;
            macE = tmp;
            tmp = C;
            C = macC;
            macC = tmp;
        }

        protected abstract void PermuteRoundsHX(short[] SX, short[] E, short[] C);

        protected abstract void PermuteRoundsKX(short[] SX, short[] E, short[] C);

        protected abstract void PermuteRoundsBX(short[] SX, short[] E, short[] C);

        public void absorbMacBlock(byte[] input, int inOff)
        {
            byteToShortXor(input, inOff, SX, BlockSize >> 1);
            PermuteRoundsHX(SX, E, C);
        }

        public void absorbFinalAADBlock()
        {
            if (m_aadPos == AADBufferSize)
            {
                absorbMacBlock(m_aad, 0);
                m_aadPos = 0;
            }
            else
            {
                for (int i = 0; i < m_aadPos; i++)
                {
                    SX[i >> 1] ^= (m_aad[i] & 0xFF) << ((i & 1) << 3);
                }
            }
            SX[m_aadPos >> 1] ^= 0x80 << ((m_aadPos & 1) << 3);
            PermuteRoundsHX(SX, E, C);

            // Domain seperation
            SX[24] ^= 0x0100;
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

        public void processMACFinal(byte[] input, int inOff, int len, byte[] tag)
        {
            if (len == BlockSize)
            {
                absorbMacBlock(input, inOff);
                len = 0;
            }
            else
            {
                // Absorb C final block
                for (int i = 0; i < len; i++)
                {
                    SX[i >> 1] ^= (input[inOff++] & 0xFF) << ((i & 1) << 3);
                }
            }
            SX[len >> 1] ^= 0x80 << ((len & 1) << 3);
            PermuteRoundsHX(SX, E, C);
            // Derive K*
            shortToByte(SX, tag);
            isap_rk(ISAP_IV2_16, tag, KEY_SIZE, SX, KEY_SIZE, C);
            // Squeeze tag
            PermuteRoundsHX(SX, E, C);
            shortToByte(SX, tag);
        }

        public void processEncBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            for (int i = 0; i < BlockSize; ++i)
            {
                output[outOff++] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ input[inOff++]);
            }
            PermuteRoundsKX(SX, E, C);
        }

        public void processEncFinalBlock(byte[] output, int outOff)
        {
            // Squeeze full or partial lane and stop
            int len = m_bufPos;
            for (int i = 0; i < len; ++i)
            {
                output[outOff++] = (byte)((SX[i >> 1] >>> ((i & 1) << 3)) ^ m_buf[i]);
            }
        }

        private void byteToShortXor(byte[] input, int inOff, short[] output, int outLen)
        {
            for (int i = 0; i < outLen; ++i)
            {
                output[i] ^= Pack.littleEndianToShort(input, inOff + (i << 1));
            }
        }

        private void byteToShort(byte[] input, short[] output, int outLen)
        {
            for (int i = 0; i < outLen; ++i)
            {
                output[i] = Pack.littleEndianToShort(input, (i << 1));
            }
        }

        private void shortToByte(short[] input, byte[] output)
        {
            for (int i = 0; i < 8; ++i)
            {
                Pack.shortToLittleEndian(input[i], output, (i << 1));
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
    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        npub = iv;
        k = key;
        m_buf = new byte[BlockSize + (forEncryption ? 0 : MAC_SIZE)];
        ISAPAEAD.init();
        initialised = true;
        m_state = forEncryption ? State.EncInit : State.DecInit;
        reset();
    }

    protected void processBufferAAD(byte[] input, int inOff)
    {
        ISAPAEAD.absorbMacBlock(input, inOff);
    }

    protected void processFinalAAD()
    {
        if (!aadFinished)
        {
            ISAPAEAD.absorbFinalAADBlock();
            ISAPAEAD.swapInternalState();
            m_aadPos = 0;
            aadFinished = true;
        }
    }

    protected void processBuffer(byte[] input, int inOff, byte[] output, int outOff)
    {
        processFinalAAD();
        ISAPAEAD.processEncBlock(input, inOff, output, outOff);
        ISAPAEAD.swapInternalState();
        if (forEncryption)
        {
            ISAPAEAD.absorbMacBlock(output, outOff);
        }
        else
        {
            ISAPAEAD.absorbMacBlock(input, inOff);
        }
        ISAPAEAD.swapInternalState();
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        processFinalAAD();
        int len = m_bufPos;
        mac = new byte[MAC_SIZE];
        ISAPAEAD.processEncFinalBlock(output, outOff);
        ISAPAEAD.swapInternalState();
        if (forEncryption)
        {
            ISAPAEAD.processMACFinal(output, outOff, len, mac);
        }
        else
        {
            ISAPAEAD.processMACFinal(m_buf, 0, len, mac);
        }
    }

    protected void reset(boolean clearMac)
    {
        if (!initialised)
        {
            throw new IllegalStateException("Need call init function before encryption/decryption");
        }
        Arrays.fill(m_buf, (byte)0);
        Arrays.fill(m_aad, (byte)0);
        ISAPAEAD.reset();
        m_bufPos = 0;
        m_aadPos = 0;
        aadFinished = false;
        super.reset(clearMac);
    }
}
