package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;

/**
 * ISAP AEAD v2, https://isap.iaik.tugraz.at/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/isap-spec-final.pdf
 * <p>
 * ISAP AEAD v2 with reference to C Reference Impl from: https://github.com/isap-lwc/isap-code-package
 * </p>
 */
public class ISAPEngine
    extends AEADBaseEngine
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
        KEY_SIZE = IV_SIZE = MAC_SIZE = 16;
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
        default:
            throw new IllegalArgumentException("Incorrect ISAP parameter");
        }
        AADBufferSize = BlockSize;
        setInnerMembers(ProcessingBufferType.Immediate, AADOperatorType.Default, DataOperatorType.Counter);
    }

    private static final int ISAP_STATE_SZ = 40;
    private byte[] k;
    private byte[] npub;
    private int ISAP_rH;
    private final ISAP_AEAD ISAPAEAD;

    private interface ISAP_AEAD
    {
        void init();

        void reset();

        void absorbMacBlock(byte[] input, int inOff);

        void absorbFinalAADBlock();

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
        AsconPermutationFriend.AsconPermutation p;
        AsconPermutationFriend.AsconPermutation mac;

        public ISAPAEAD_A()
        {
            ISAP_rH = 64;
            BlockSize = (ISAP_rH + 7) >> 3;
            p = new AsconPermutationFriend.AsconPermutation();
            mac = new AsconPermutationFriend.AsconPermutation();
        }

        public void init()
        {
            npub64 = new long[getLongSize(npub.length)];
            k64 = new long[getLongSize(k.length)];
            Pack.bigEndianToLong(npub, 0, npub64);
            Pack.bigEndianToLong(k, 0, k64);
        }

        protected abstract void PX1(AsconPermutationFriend.AsconPermutation p);

        protected abstract void PX2(AsconPermutationFriend.AsconPermutation p);

        public void absorbMacBlock(byte[] input, int inOff)
        {
            mac.x0 ^= Pack.bigEndianToLong(input, inOff);
            mac.p(12);
        }

        public void absorbFinalAADBlock()
        {
            for (int i = 0; i < m_aadPos; ++i)
            {
                mac.x0 ^= (m_aad[i] & 0xFFL) << ((7 - i) << 3);
            }
            mac.x0 ^= 0x80L << ((7 - m_aadPos) << 3);
            mac.p(12);
            mac.x4 ^= 1L;
        }

        public void processMACFinal(byte[] input, int inOff, int len, byte[] tag)
        {
            for (int i = 0; i < len; ++i)
            {
                mac.x0 ^= (input[inOff++] & 0xFFL) << ((7 - i) << 3);
            }
            mac.x0 ^= 0x80L << ((7 - len) << 3);
            mac.p(12);
            // Derive K*
            Pack.longToBigEndian(mac.x0, tag, 0);
            Pack.longToBigEndian(mac.x1, tag, 8);
            long tmp_x2 = mac.x2, tmp_x3 = mac.x3, tmp_x4 = mac.x4;
            isap_rk(mac, ISAP_IV2_64, tag, KEY_SIZE);
            mac.x2 = tmp_x2;
            mac.x3 = tmp_x3;
            mac.x4 = tmp_x4;
            // Squeeze tag
            mac.p(12);
            Pack.longToBigEndian(mac.x0, tag, 0);
            Pack.longToBigEndian(mac.x1, tag, 8);
        }

        private void isap_rk(AsconPermutationFriend.AsconPermutation p, long iv64, byte[] y, int ylen)
        {
            // Init state
            p.set(k64[0], k64[1], iv64, 0L, 0L);
            p.p(12);
            // Absorb Y
            for (int i = 0; i < (ylen << 3) - 1; i++)
            {
                p.x0 ^= ((((y[i >>> 3] >>> (7 - (i & 7))) & 0x01) << 7) & 0xFFL) << 56;
                PX2(p);
            }
            p.x0 ^= (((y[ylen - 1]) & 0x01L) << 7) << 56;
            p.p(12);
        }

        public void processEncBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            Pack.longToBigEndian(Pack.bigEndianToLong(input, inOff) ^ p.x0, output, outOff);
            PX1(p);
        }

        public void processEncFinalBlock(byte[] output, int outOff)
        {
            /* Encrypt final m block */
            byte[] xo = Pack.longToLittleEndian(p.x0);
            Bytes.xor(m_bufPos, xo, BlockSize - m_bufPos, m_buf, 0, output, outOff);
        }

        public void reset()
        {
            // Init state
            isap_rk(p, ISAP_IV3_64, npub, IV_SIZE);
            p.x3 = npub64[0];
            p.x4 = npub64[1];
            PX1(p);
            // Init State for mac
            mac.set(npub64[0], npub64[1], ISAP_IV1_64, 0L, 0L);
            mac.p(12);
        }

        private int getLongSize(int x)
        {
            return ((x + 7) >>> 3);
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

        protected void PX1(AsconPermutationFriend.AsconPermutation p)
        {
            p.p(6);
        }

        protected void PX2(AsconPermutationFriend.AsconPermutation p)
        {
            p.round(0x4bL);
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

        protected void PX1(AsconPermutationFriend.AsconPermutation p)
        {
            p.p(12);
        }

        protected void PX2(AsconPermutationFriend.AsconPermutation p)
        {
            p.p(12);
        }
    }

    private abstract class ISAPAEAD_K
        implements ISAP_AEAD
    {
        protected final int ISAP_STATE_SZ_CRYPTO_NPUBBYTES = ISAP_STATE_SZ - IV_SIZE;
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
            Pack.littleEndianToShort(k, 0, k16, 0, k16.length);
            iv16 = new short[npub.length >> 1];
            Pack.littleEndianToShort(npub, 0, iv16, 0, iv16.length);
        }

        public void reset()
        {
            // Init state
            Arrays.fill(SX, (byte)0);
            isap_rk(ISAP_IV3_16, npub, IV_SIZE, SX, ISAP_STATE_SZ_CRYPTO_NPUBBYTES, C);
            System.arraycopy(iv16, 0, SX, 17, 8);
            PermuteRoundsKX(SX, E, C);
            // Init state for mac
            Arrays.fill(macSX, 12, 25, (short)0);
            System.arraycopy(iv16, 0, macSX, 0, 8);
            System.arraycopy(ISAP_IV1_16, 0, macSX, 8, 4);
            PermuteRoundsHX(macSX, macE, macC);
        }

        protected abstract void PermuteRoundsHX(short[] SX, short[] E, short[] C);

        protected abstract void PermuteRoundsKX(short[] SX, short[] E, short[] C);

        protected abstract void PermuteRoundsBX(short[] SX, short[] E, short[] C);

        public void absorbMacBlock(byte[] input, int inOff)
        {
            byteToShortXor(input, inOff, macSX, BlockSize >> 1);
            PermuteRoundsHX(macSX, macE, macC);
        }

        public void absorbFinalAADBlock()
        {
            for (int i = 0; i < m_aadPos; i++)
            {
                macSX[i >> 1] ^= (m_aad[i] & 0xFF) << ((i & 1) << 3);
            }
            macSX[m_aadPos >> 1] ^= 0x80 << ((m_aadPos & 1) << 3);
            PermuteRoundsHX(macSX, macE, macC);

            // Domain seperation
            macSX[24] ^= 0x0100;
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
            // Absorb C final block
            for (int i = 0; i < len; i++)
            {
                macSX[i >> 1] ^= (input[inOff++] & 0xFF) << ((i & 1) << 3);
            }

            macSX[len >> 1] ^= 0x80 << ((len & 1) << 3);
            PermuteRoundsHX(macSX, macE, macC);
            // Derive K*
            Pack.shortToLittleEndian(macSX, 0, 8, tag, 0);
            isap_rk(ISAP_IV2_16, tag, KEY_SIZE, macSX, KEY_SIZE, macC);
            // Squeeze tag
            PermuteRoundsHX(macSX, macE, macC);
            Pack.shortToLittleEndian(macSX, 0, 8, tag, 0);
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
            for (int i = 0; i < m_bufPos; ++i)
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
        ISAPAEAD.init();
    }

    protected void processBufferAAD(byte[] input, int inOff)
    {
        ISAPAEAD.absorbMacBlock(input, inOff);
    }

    protected void processFinalAAD()
    {
        ISAPAEAD.absorbFinalAADBlock();
    }

    @Override
    protected void finishAAD(State nextState, boolean isDoFinal)
    {
        finishAAD3(nextState, isDoFinal);
    }

    protected void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        ISAPAEAD.processEncBlock(input, inOff, output, outOff);
        ISAPAEAD.absorbMacBlock(output, outOff);
    }

    protected void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        ISAPAEAD.processEncBlock(input, inOff, output, outOff);
        ISAPAEAD.absorbMacBlock(input, inOff);
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        ISAPAEAD.processEncFinalBlock(output, outOff);
        if (forEncryption)
        {
            ISAPAEAD.processMACFinal(output, outOff, m_bufPos, mac);
        }
        else
        {
            ISAPAEAD.processMACFinal(m_buf, 0, m_bufPos, mac);
        }
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        ISAPAEAD.reset();
    }
}
