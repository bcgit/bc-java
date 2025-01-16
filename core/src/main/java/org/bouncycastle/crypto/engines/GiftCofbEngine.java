package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * GIFT-COFB v1.1, based on the current round 3 submission, https://www.isical.ac.in/~lightweight/COFB/
 * Reference C implementation: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/elephant.zip
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/gift-cofb-spec-final.pdf
 */

public class GiftCofbEngine
    implements AEADBlockCipher
{
    private final int CRYPTO_ABYTES = 16;
    private boolean forEncryption;
    private boolean initialised = false;
    private byte[] npub;
    private byte[] k;
    private byte[] Y;
    private byte[] mac;
    private byte[] input;
    private byte[] offset;
    private boolean encrypted;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    /*Round constants*/
    private final byte[] GIFT_RC = {
        (byte)0x01, (byte)0x03, (byte)0x07, (byte)0x0F, (byte)0x1F, (byte)0x3E, (byte)0x3D, (byte)0x3B, (byte)0x37, (byte)0x2F,
        (byte)0x1E, (byte)0x3C, (byte)0x39, (byte)0x33, (byte)0x27, (byte)0x0E, (byte)0x1D, (byte)0x3A, (byte)0x35, (byte)0x2B,
        (byte)0x16, (byte)0x2C, (byte)0x18, (byte)0x30, (byte)0x21, (byte)0x02, (byte)0x05, (byte)0x0B, (byte)0x17, (byte)0x2E,
        (byte)0x1C, (byte)0x38, (byte)0x31, (byte)0x23, (byte)0x06, (byte)0x0D, (byte)0x1B, (byte)0x36, (byte)0x2D, (byte)0x1A
    };

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

    private void xor_block(byte[] d, int dOff, byte[] s1, byte[] s2, int s2Off, int no_of_bytes)
    {
        for (int i = 0; i < no_of_bytes; i++)
        {
            d[i + dOff] = (byte)(s1[i] ^ s2[i + s2Off]);
        }
    }

    private void xor_topbar_block(byte[] d, byte[] s1, byte[] s2)
    {
        for (int i = 0; i < 8; i++)
        {
            d[i] = (byte)(s1[i] ^ s2[i]);
        }
        System.arraycopy(s1, 8, d, 8, 8);
    }

    private void double_half_block(byte[] d, byte[] s)
    {
        int i;
        byte[] tmp = new byte[8];
        /*x^{64} + x^4 + x^3 + x + 1*/
        for (i = 0; i < 7; i++)
        {
            tmp[i] = (byte)(((s[i] & 0xFF) << 1) | ((s[i + 1] & 0xFF) >>> 7));
        }
        tmp[7] = (byte)(((s[7] & 0xFF) << 1) ^ (((s[0] & 0xFF) >>> 7) * 27));
        System.arraycopy(tmp, 0, d, 0, 8);
    }

    private void triple_half_block(byte[] d, byte[] s)
    {
        byte[] tmp = new byte[8];
        double_half_block(tmp, s);
        for (int i = 0; i < 8; i++)
        {
            d[i] = (byte)(s[i] ^ tmp[i]);
        }
    }

    private void pho1(byte[] d, byte[] Y, byte[] M, int mOff, int no_of_bytes)
    {
        byte[] tmpM = new byte[16];
        //padding(tmpM, M, mOff, no_of_bytes);
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
        int i;
        //G(Y, Y);
        /*Y[1],Y[2] -> Y[2],Y[1]<<<1*/
        System.arraycopy(Y, 8, tmp, 0, 8);
        for (i = 0; i < 7; i++)
        {
            tmp[i + 8] = (byte)((Y[i] & 0xFF) << 1 | (Y[i + 1] & 0xFF) >>> 7);
        }
        tmp[15] = (byte)((Y[7] & 0xFF) << 1 | (Y[0] & 0xFF) >>> 7);
        System.arraycopy(tmp, 0, Y, 0, 16);
        xor_block(d, 0, Y, tmpM, 0, 16);
    }

    private void pho(byte[] Y, byte[] M, int mOff, byte[] X, byte[] C, int cOff, int no_of_bytes)
    {
        xor_block(C, cOff, Y, M, mOff, no_of_bytes);
        pho1(X, Y, M, mOff, no_of_bytes);
    }

    private void phoprime(byte[] Y, byte[] C, int cOff, byte[] X, byte[] M, int mOff, int no_of_bytes)
    {
        xor_block(M, mOff, Y, C, cOff, no_of_bytes);
        pho1(X, Y, M, mOff, no_of_bytes);
    }

    private void processAAD(boolean emptyM)
    {
        byte[] a = aadData.toByteArray();
        int alen = aadData.size();
        int aOff = 0;
        boolean emptyA = (alen == 0);
        /*Process AD*/
        /*non-empty A*/
        /*full blocks*/
        while (alen > 16)
        {
            /* X[i] = (A[i] + G(Y[i-1])) + offset */
            pho1(input, Y, a, aOff, 16);
            /* offset = 2*offset */
            double_half_block(offset, offset);
            xor_topbar_block(input, input, offset);
            /* Y[i] = E(X[i]) */
            giftb128(input, k, Y);
            aOff += 16;
            alen -= 16;
        }
        /* last byte[] */
        /* full byte[]: offset = 3*offset */
        /* partial byte[]: offset = 3^2*offset */
        triple_half_block(offset, offset);
        if (((alen & 15) != 0) || emptyA)
        {
            triple_half_block(offset, offset);
        }
        if (emptyM)
        {
            /* empty M: offset = 3^2*offset */
            triple_half_block(offset, offset);
            triple_half_block(offset, offset);
        }
        /* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
        pho1(input, Y, a, aOff, alen);
        xor_topbar_block(input, input, offset);
        /* Y[a] = E(X[a]) */
        giftb128(input, k, Y);
    }

    private int cofb_crypt(byte[] output, int outOff, byte[] k, byte[] intputM, int inOff, int inlen)
    {
        int rv = 0;
        /* Process M */
        /* full byte[]s */
        while (inlen > 16)
        {
            double_half_block(offset, offset);
            /* C[i] = Y[i+a-1] + M[i]*/
            /* X[i] = M[i] + G(Y[i+a-1]) + offset */
            if (forEncryption)
            {
                pho(Y, intputM, inOff, input, output, outOff, 16);
            }
            else
            {
                phoprime(Y, intputM, inOff, input, output, outOff, 16);
            }
            xor_topbar_block(input, input, offset);
            /* Y[i] = E(X[i+a]) */
            giftb128(input, k, Y);
            inOff += 16;
            outOff += 16;
            inlen -= 16;
            rv += 16;
            encrypted = true;
        }
        return rv;
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
        this.forEncryption = forEncryption;
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException("Gift-Cofb init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV)params;
        npub = ivParams.getIV();
        if (npub == null || npub.length != 16)
        {
            throw new IllegalArgumentException("Gift-Cofb requires exactly 16 bytes of IV");
        }
        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException("Gift-Cofb init parameters must include a key");
        }
        KeyParameter key = (KeyParameter)ivParams.getParameters();
        k = key.getKey();
        if (k.length != 16)
        {
            throw new IllegalArgumentException("Gift-Cofb key must be 128 bits long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        /*Mask-Gen*/
        Y = new byte[CRYPTO_ABYTES];
        input = new byte[16];
        offset = new byte[8];
        initialised = true;
        reset(false);
    }

    @Override
    public String getAlgorithmName()
    {
        return "GIFT-COFB AEAD";
    }

    @Override
    public void processAADByte(byte in)
    {
        if (encrypted)
        {
            throw new IllegalArgumentException("Gift-Cofb: AAD cannot be added after reading a full block(" +
                CRYPTO_ABYTES + " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
        }
        aadData.write(in);
    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (encrypted)
        {
            throw new IllegalArgumentException("Gift-Cofb: AAD cannot be added after reading a full block(" +
                CRYPTO_ABYTES + " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
        }
        if (inOff + len > in.length)
        {
            throw new DataLengthException("Gift-Cofb input buffer too short");
        }
        aadData.write(in, inOff, len);
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Gift-Cofb needs call init function before processByte");
        }
        message.write(in);
        return 0;
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Gift-Cofb  needs call init function before processBytes");
        }
        if (inOff + len > in.length)
        {
            throw new DataLengthException("Gift-Cofb input buffer too short");
        }
        message.write(in, inOff, len);
        int inlen = message.size() - (forEncryption ? 0 : 16);
        int rv = inlen - (inlen & 15);
        if (outOff + rv > out.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        rv = 0;
        if (inlen > 16)
        {
            processAAD(false);
            encrypted = true;
            byte[] input = message.toByteArray();
            rv = cofb_crypt(out, outOff, k, input, 0, inlen);
            if (rv < inlen)
            {
                message.reset();
                message.write(input, rv, inlen - rv + (forEncryption ? 0 : 16));
            }
        }
        return rv;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Gift-Cofb needs call init function before doFinal");
        }
        int inlen = message.size() - (forEncryption ? 0 : CRYPTO_ABYTES);
        if ((forEncryption && inlen + CRYPTO_ABYTES + outOff > output.length) ||
            (!forEncryption && inlen + outOff > output.length))
        {
            throw new OutputLengthException("output buffer is too short");
        }

        if (!encrypted)
        {
            processAAD(inlen == 0);
        }
        int inOff = 0;
        byte[] intputM = message.toByteArray();

        if (encrypted || inlen != 0)
        {
            /* full block: offset = 3*offset */
            /* empty data / partial block: offset = 3^2*offset */
            triple_half_block(offset, offset);
            if ((inlen & 15) != 0)
            {
                triple_half_block(offset, offset);
            }
            /* last block */
            /* C[m] = Y[m+a-1] + M[m]*/
            /* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
            if (forEncryption)
            {
                pho(Y, intputM, inOff, input, output, outOff, inlen);
                outOff += inlen;
            }
            else
            {
                phoprime(Y, intputM, inOff, input, output, outOff, inlen);
                inOff += inlen;
            }
            xor_topbar_block(input, input, offset);
            /* T = E(X[m+a]) */
            giftb128(input, k, Y);
        }
        if (forEncryption)
        {
            System.arraycopy(Y, 0, output, outOff, CRYPTO_ABYTES);
            mac = new byte[CRYPTO_ABYTES];
            System.arraycopy(Y, 0, mac, 0, CRYPTO_ABYTES);
            inlen += CRYPTO_ABYTES;
        }
        else
        {
            for (int i = 0; i < CRYPTO_ABYTES; ++i)
            {
                if (Y[i] != intputM[inOff + i])
                {
                    throw new InvalidCipherTextException("mac check in Gift-Cofb failed");
                }
            }
        }
        reset(false);
        return inlen;
    }

    @Override
    public byte[] getMac()
    {
        return mac;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Gift-Cofb needs call init function before getUpdateOutputSize");
        }
        int totalData = message.size() + len;
        if (!forEncryption)
        {
            if (totalData < CRYPTO_ABYTES)
            {
                return 0;
            }
            totalData -= CRYPTO_ABYTES;
        }
        return totalData - totalData % CRYPTO_ABYTES;
    }

    @Override
    public int getOutputSize(int len)
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Gift-Cofb needs call init function before getOutputSize");
        }
        int totalData = message.size() + len;
        if (forEncryption)
        {
            return totalData + CRYPTO_ABYTES;
        }
        return Math.max(0, totalData - CRYPTO_ABYTES);
    }

    @Override
    public void reset()
    {
        reset(true);
    }

    private void reset(boolean clearMac)
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Gift-Cofb needs call init function before reset");
        }
        if (clearMac)
        {
            mac = null;
        }
        /*nonce is 128-bit*/
        System.arraycopy(npub, 0, input, 0, 16);
        giftb128(input, k, Y);
        System.arraycopy(Y, 0, offset, 0, 8);
        aadData.reset();
        message.reset();
        encrypted = false;
    }
}
