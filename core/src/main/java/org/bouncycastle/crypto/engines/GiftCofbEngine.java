package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Bytes;

/**
 * GIFT-COFB v1.1, based on the current round 3 submission, https://www.isical.ac.in/~lightweight/COFB/
 * Reference C implementation: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/elephant.zip
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
 */

public class GiftCofbEngine
    extends AEADBaseEngine
{
    private byte[] npub;
    private byte[] k;
    private byte[] Y;
    private byte[] input;
    private byte[] offset;
    /*Round constants*/
    private static final byte[] GIFT_RC = {
        (byte)0x01, (byte)0x03, (byte)0x07, (byte)0x0F, (byte)0x1F, (byte)0x3E, (byte)0x3D, (byte)0x3B, (byte)0x37, (byte)0x2F,
        (byte)0x1E, (byte)0x3C, (byte)0x39, (byte)0x33, (byte)0x27, (byte)0x0E, (byte)0x1D, (byte)0x3A, (byte)0x35, (byte)0x2B,
        (byte)0x16, (byte)0x2C, (byte)0x18, (byte)0x30, (byte)0x21, (byte)0x02, (byte)0x05, (byte)0x0B, (byte)0x17, (byte)0x2E,
        (byte)0x1C, (byte)0x38, (byte)0x31, (byte)0x23, (byte)0x06, (byte)0x0D, (byte)0x1B, (byte)0x36, (byte)0x2D, (byte)0x1A
    };

    public GiftCofbEngine()
    {
        AADBufferSize = BlockSize = MAC_SIZE = IV_SIZE = KEY_SIZE = 16;
        algorithmName = "GIFT-COFB AEAD";
        setInnerMembers(ProcessingBufferType.Buffered, AADOperatorType.Default, DataOperatorType.Counter);
    }

    private int rowperm(int S, int B0_pos, int B1_pos, int B2_pos, int B3_pos)
    {
        int T = 0;
        int b;
        for (b = 0; b < 8; b++)
        {
            T |= ((S >>> (4 * b)) & 0x1) << (b + 8 * B0_pos);
            T |= ((S >>> (4 * b + 1)) & 0x1) << (b + 8 * B1_pos);
            T |= ((S >>> (4 * b + 2)) & 0x1) << (b + 8 * B2_pos);
            T |= ((S >>> (4 * b + 3)) & 0x1) << (b + 8 * B3_pos);
        }
        return T;
    }

    private void giftb128(byte[] P, byte[] K, byte[] C)
    {
        int round, T;
        int[] S = new int[4];
        short[] W = new short[8];
        short T6, T7;
        S[0] = ((P[0] & 0xFF) << 24) | ((P[1] & 0xFF) << 16) | ((P[2] & 0xFF) << 8) | (P[3] & 0xFF);
        S[1] = ((P[4] & 0xFF) << 24) | ((P[5] & 0xFF) << 16) | ((P[6] & 0xFF) << 8) | (P[7] & 0xFF);
        S[2] = ((P[8] & 0xFF) << 24) | ((P[9] & 0xFF) << 16) | ((P[10] & 0xFF) << 8) | (P[11] & 0xFF);
        S[3] = ((P[12] & 0xFF) << 24) | ((P[13] & 0xFF) << 16) | ((P[14] & 0xFF) << 8) | (P[15] & 0xFF);
        W[0] = (short)(((K[0] & 0xFF) << 8) | (K[1] & 0xFF));
        W[1] = (short)(((K[2] & 0xFF) << 8) | (K[3] & 0xFF));
        W[2] = (short)(((K[4] & 0xFF) << 8) | (K[5] & 0xFF));
        W[3] = (short)(((K[6] & 0xFF) << 8) | (K[7] & 0xFF));
        W[4] = (short)(((K[8] & 0xFF) << 8) | (K[9] & 0xFF));
        W[5] = (short)(((K[10] & 0xFF) << 8) | (K[11] & 0xFF));
        W[6] = (short)(((K[12] & 0xFF) << 8) | (K[13] & 0xFF));
        W[7] = (short)(((K[14] & 0xFF) << 8) | (K[15] & 0xFF));
        for (round = 0; round < 40; round++)
        {
            /*===SubCells===*/
            S[1] ^= S[0] & S[2];
            S[0] ^= S[1] & S[3];
            S[2] ^= S[0] | S[1];
            S[3] ^= S[2];
            S[1] ^= S[3];
            S[3] ^= 0xffffffff;
            S[2] ^= S[0] & S[1];
            T = S[0];
            S[0] = S[3];
            S[3] = T;
            /*===PermBits===*/
            S[0] = rowperm(S[0], 0, 3, 2, 1);
            S[1] = rowperm(S[1], 1, 0, 3, 2);
            S[2] = rowperm(S[2], 2, 1, 0, 3);
            S[3] = rowperm(S[3], 3, 2, 1, 0);
            /*===AddRoundKey===*/
            S[2] ^= ((W[2] & 0xFFFF) << 16) | (W[3] & 0xFFFF);
            S[1] ^= ((W[6] & 0xFFFF) << 16) | (W[7] & 0xFFFF);
            /*Add round constant*/
            S[3] ^= 0x80000000 ^ (GIFT_RC[round] & 0xFF);
            /*===Key state update===*/
            T6 = (short)(((W[6] & 0xFFFF) >>> 2) | ((W[6] & 0xFFFF) << 14));
            T7 = (short)(((W[7] & 0xFFFF) >>> 12) | ((W[7] & 0xFFFF) << 4));
            W[7] = W[5];
            W[6] = W[4];
            W[5] = W[3];
            W[4] = W[2];
            W[3] = W[1];
            W[2] = W[0];
            W[1] = T7;
            W[0] = T6;
        }
        C[0] = (byte)(S[0] >>> 24);
        C[1] = (byte)(S[0] >>> 16);
        C[2] = (byte)(S[0] >>> 8);
        C[3] = (byte)(S[0]);
        C[4] = (byte)(S[1] >>> 24);
        C[5] = (byte)(S[1] >>> 16);
        C[6] = (byte)(S[1] >>> 8);
        C[7] = (byte)(S[1]);
        C[8] = (byte)(S[2] >>> 24);
        C[9] = (byte)(S[2] >>> 16);
        C[10] = (byte)(S[2] >>> 8);
        C[11] = (byte)(S[2]);
        C[12] = (byte)(S[3] >>> 24);
        C[13] = (byte)(S[3] >>> 16);
        C[14] = (byte)(S[3] >>> 8);
        C[15] = (byte)(S[3]);
    }

    private void double_half_block(byte[] s)
    {
        int mask = ((s[0] & 0xFF) >>> 7) * 27;
        /*x^{64} + x^4 + x^3 + x + 1*/
        for (int i = 0; i < 7; i++)
        {
            s[i] = (byte)(((s[i] & 0xFF) << 1) | ((s[i + 1] & 0xFF) >>> 7));
        }
        s[7] = (byte)(((s[7] & 0xFF) << 1) ^ mask);
    }

    private void triple_half_block(byte[] s)
    {
        byte[] tmp = new byte[8];
        /*x^{64} + x^4 + x^3 + x + 1*/
        for (int i = 0; i < 7; i++)
        {
            tmp[i] = (byte)(((s[i] & 0xFF) << 1) | ((s[i + 1] & 0xFF) >>> 7));
        }
        tmp[7] = (byte)(((s[7] & 0xFF) << 1) ^ (((s[0] & 0xFF) >>> 7) * 27));
        Bytes.xorTo(8, tmp, s);
    }

    private void pho1(byte[] d, byte[] Y, byte[] M, int mOff, int no_of_bytes)
    {
        byte[] tmpM = new byte[16];
        byte[] tmp = new byte[16];
        if (no_of_bytes == 0)
        {
            tmpM[0] = (byte)0x80;
        }
        else if (no_of_bytes < 16)
        {
            System.arraycopy(M, mOff, tmpM, 0, no_of_bytes);
            tmpM[no_of_bytes] = (byte)0x80;
        }
        else
        {
            System.arraycopy(M, mOff, tmpM, 0, no_of_bytes);
        }
        //G(Y, Y);
        /*Y[1],Y[2] -> Y[2],Y[1]<<<1*/
        System.arraycopy(Y, 8, tmp, 0, 8);
        for (int i = 0; i < 7; i++)
        {
            tmp[i + 8] = (byte)((Y[i] & 0xFF) << 1 | (Y[i + 1] & 0xFF) >>> 7);
        }
        tmp[15] = (byte)((Y[7] & 0xFF) << 1 | (Y[0] & 0xFF) >>> 7);
        System.arraycopy(tmp, 0, Y, 0, 16);
        Bytes.xor(16, Y, tmpM, d);
    }

    @Override
    protected void processBufferAAD(byte[] in, int inOff)
    {
        pho1(input, Y, in, inOff, 16);
        /* offset = 2*offset */
        double_half_block(offset);
        Bytes.xorTo(8, offset, input);
        /* Y[i] = E(X[i]) */
        giftb128(input, k, Y);
    }

    @Override
    protected void processFinalAAD()
    {
        int len = dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE);
        /* last byte[] */
        /* full byte[]: offset = 3*offset */
        /* partial byte[]: offset = 3^2*offset */
        triple_half_block(offset);
        if (((m_aadPos & 15) != 0) || m_state == State.DecInit || m_state == State.EncInit)
        {
            triple_half_block(offset);
        }
        if (len == 0)
        {
            /* empty M: offset = 3^2*offset */
            triple_half_block(offset);
            triple_half_block(offset);
        }
        /* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
        pho1(input, Y, m_aad, 0, m_aadPos);
        Bytes.xorTo(8, offset, input);
        /* Y[a] = E(X[a]) */
        giftb128(input, k, Y);
    }

    @Override
    protected void finishAAD(State nextState, boolean isDoFinal)
    {
        finishAAD3(nextState, isDoFinal);
    }

    @Override
    protected void init(byte[] key, byte[] iv)
    {
        npub = iv;
        k = key;
        Y = new byte[BlockSize];
        input = new byte[16];
        offset = new byte[8];
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        int len = dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE);
        if (len != 0)
        {
            /* full block: offset = 3*offset */
            /* empty data / partial block: offset = 3^2*offset */
            triple_half_block(offset);
            if ((len & 15) != 0)
            {
                triple_half_block(offset);
            }
            /* last block */
            /* C[m] = Y[m+a-1] + M[m]*/
            /* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
            Bytes.xor(m_bufPos, Y, m_buf, 0, output, outOff);
            if (forEncryption)
            {
                pho1(input, Y, m_buf, 0, m_bufPos);
            }
            else
            {
                pho1(input, Y, output, outOff, m_bufPos);
            }
            Bytes.xorTo(8, offset, input);
            /* T = E(X[m+a]) */
            giftb128(input, k, Y);
        }
        System.arraycopy(Y, 0, mac, 0, BlockSize);
    }

    @Override
    protected void processBufferEncrypt(byte[] inputM, int inOff, byte[] output, int outOff)
    {
        /* Process M */
        /* full byte[]s */
        double_half_block(offset);
        /* C[i] = Y[i+a-1] + M[i]*/
        /* X[i] = M[i] + G(Y[i+a-1]) + offset */
        Bytes.xor(BlockSize, Y, inputM, inOff, output, outOff);
        pho1(input, Y, inputM, inOff, BlockSize);
        Bytes.xorTo(8, offset, input);
        /* Y[i] = E(X[i+a]) */
        giftb128(input, k, Y);
    }

    @Override
    protected void processBufferDecrypt(byte[] inputM, int inOff, byte[] output, int outOff)
    {
        /* Process M */
        /* full byte[]s */
        double_half_block(offset);
        /* C[i] = Y[i+a-1] + M[i]*/
        /* X[i] = M[i] + G(Y[i+a-1]) + offset */
        Bytes.xor(BlockSize, Y, inputM, inOff, output, outOff);
        pho1(input, Y, output, outOff, BlockSize);
        Bytes.xorTo(8, offset, input);
        /* Y[i] = E(X[i+a]) */
        giftb128(input, k, Y);
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        /*nonce is 128-bit*/
        System.arraycopy(npub, 0, input, 0, IV_SIZE);
        giftb128(input, k, Y);
        System.arraycopy(Y, 0, offset, 0, 8);
    }
}
