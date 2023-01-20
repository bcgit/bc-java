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
import org.bouncycastle.util.Pack;


/**
 * ASCON AEAD v1.2, https://ascon.iaik.tugraz.at/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 * <p>
 * ASCON AEAD v1.2 with reference to C Reference Impl from: https://github.com/ascon/ascon-c
 * </p>
 */


public class AsconEngine
    implements AEADBlockCipher
{
    public enum AsconParameters
    {
        ascon80pq,
        ascon128a,
        ascon128
    }

    private boolean forEncryption;

    private final AsconParameters asconParameters;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private byte[] mac;

    private String algorithmName;
    private boolean encrypted;
    private boolean initialised;
    private boolean aadFinished;
    private final int CRYPTO_KEYBYTES;
    private final int CRYPTO_ABYTES;
    private final int ASCON_AEAD_RATE;
    private final int nr;
    private long K0;
    private long K1;
    private long K2;
    private long N0;
    private long N1;
    private final long ASCON_IV;
    private long x0;
    private long x1;
    private long x2;
    private long x3;
    private long x4;

    public AsconEngine(AsconParameters asconParameters)
    {
        this.asconParameters = asconParameters;
        switch (asconParameters)
        {
        case ascon80pq:
            CRYPTO_KEYBYTES = 20;
            CRYPTO_ABYTES = 16;
            ASCON_AEAD_RATE = 8;
            ASCON_IV = 0xa0400c0600000000L;
            algorithmName = "Ascon-80pq AEAD";
            break;
        case ascon128a:
            CRYPTO_KEYBYTES = 16;
            CRYPTO_ABYTES = 16;
            ASCON_AEAD_RATE = 16;
            ASCON_IV = 0x80800c0800000000L;
            algorithmName = "Ascon-128a AEAD";
            break;
        case ascon128:
            CRYPTO_KEYBYTES = 16;
            CRYPTO_ABYTES = 16;
            ASCON_AEAD_RATE = 8;
            ASCON_IV = 0x80400c0600000000L;
            algorithmName = "Ascon-128 AEAD";
            break;
        default:
            throw new IllegalArgumentException("invalid parameter setting for ASCON AEAD");
        }
        nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
        initialised = false;
        aadFinished = false;
    }

    private long U64BIG(long x)
    {
        return (((0x00000000000000FFL & (x)) << 56) |
            ((0x000000000000FF00L & (x)) << 40) |
            ((0x0000000000FF0000L & (x)) << 24) |
            ((0x00000000FF000000L & (x)) << 8) |
            ((0x000000FF00000000L & (x)) >>> 8) |
            ((0x0000FF0000000000L & (x)) >>> 24) |
            ((0x00FF000000000000L & (x)) >>> 40) |
            ((0xFF00000000000000L & (x)) >>> 56));
    }

    private long ROR(long x, int n)
    {
        return x >>> n | x << (64 - n);
    }

    private long KEYROT(long lo2hi, long hi2lo)
    {
        return lo2hi << 32 | hi2lo >>> 32;
    }

    private long PAD(int i)
    {
        return 0x80L << (56 - (i << 3));
    }

    private long MASK(int n)
    {
        /* undefined for n == 0 */
        return ~0L >>> (64 - (n << 3));
    }

    private long LOAD(final byte[] bytes, int inOff, int n)
    {
        long x = 0;
        for (int i = 0; i < n; ++i)
        {
            x |= (bytes[i + inOff] & 0xFFL) << (i << 3);
        }
        return U64BIG(x & MASK(n));
    }

    private void STORE(byte[] bytes, int inOff, long w, int n)
    {
        long x = 0;
        for (int i = 0; i < n; ++i)
        {
            x |= (bytes[i + inOff] & 0xFFL) << (i << 3);
        }
        //long x = Pack.littleEndianToLong(bytes, inOff);
        x &= ~MASK(n);
        x |= U64BIG(w);
        for (int i = 0; i < n; ++i)
        {
            bytes[i + inOff] = (byte)(x >>> (i << 3));
        }
//        Pack.longToLittleEndian(x, bytes, inOff);
    }

    private long LOADBYTES(final byte[] bytes, int inOff, int n)
    {
        long x = 0;
        for (int i = 0; i < n; ++i)
        {
            x |= (bytes[i + inOff] & 0xFFL) << ((7 - i) << 3);
        }
        return x;
    }

    private void STOREBYTES(byte[] bytes, int inOff, long w, int n)
    {
        for (int i = 0; i < n; ++i)
        {
            bytes[i + inOff] = (byte)(w >>> ((7 - i) << 3));
        }
    }

    private void ROUND(long C)
    {
        long t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
        long t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
        long t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
        long t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
        long t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
        x0 = t0 ^ ROR(t0, 19) ^ ROR(t0, 28);
        x1 = t1 ^ ROR(t1, 39) ^ ROR(t1, 61);
        x2 = ~(t2 ^ ROR(t2, 1) ^ ROR(t2, 6));
        x3 = t3 ^ ROR(t3, 10) ^ ROR(t3, 17);
        x4 = t4 ^ ROR(t4, 7) ^ ROR(t4, 41);
    }

    private void P(int nr)
    {
        if (nr == 12)
        {
            ROUND(0xf0L);
            ROUND(0xe1L);
            ROUND(0xd2L);
            ROUND(0xc3L);
        }
        if (nr >= 8)
        {
            ROUND(0xb4L);
            ROUND(0xa5L);
        }
        ROUND(0x96L);
        ROUND(0x87L);
        ROUND(0x78L);
        ROUND(0x69L);
        ROUND(0x5aL);
        ROUND(0x4bL);
    }

    private void ascon_aeadinit()
    {
        /* initialize */
        x0 ^= ASCON_IV;
        if (CRYPTO_KEYBYTES == 20)
        {
            x0 ^= K0;
        }
        x1 ^= K1;
        x2 ^= K2;
        x3 ^= N0;
        x4 ^= N1;
        P(12);
        if (CRYPTO_KEYBYTES == 20)
        {
            x2 ^= K0;
        }
        x3 ^= K1;
        x4 ^= K2;
    }

    private void ascon_adata(final byte[] ad, int adOff, int adlen)
    {
        if (adlen != 0)
        {
            /* full associated data blocks */
            while (adlen >= ASCON_AEAD_RATE)
            {
                x0 ^= LOAD(ad, adOff, 8);
                if (ASCON_AEAD_RATE == 16)
                {
                    x1 ^= LOAD(ad, adOff + 8, 8);
                }
                P(nr);
                adOff += ASCON_AEAD_RATE;
                adlen -= ASCON_AEAD_RATE;
            }
            /* final associated data block */
            if (ASCON_AEAD_RATE == 16 && adlen >= 8)
            {
                x0 ^= LOAD(ad, adOff, 8);
                adOff += 8;
                adlen -= 8;
                x1 ^= PAD(adlen);
                if (adlen != 0)
                {
                    x1 ^= LOAD(ad, adOff, adlen);
                }
            }
            else
            {
                x0 ^= PAD(adlen);
                if (adlen != 0)
                {
                    x0 ^= LOAD(ad, adOff, adlen);
                }
            }
            P(nr);
        }
        /* domain separation */
        x4 ^= 1L;
    }

    private void ascon_encrypt(byte[] c, int cOff, final byte[] m, int mOff, int mlen)
    {
        /* full plaintext blocks */
        while (mlen >= ASCON_AEAD_RATE)
        {
            x0 ^= LOAD(m, mOff, 8);
            STORE(c, cOff, x0, 8);
            if (ASCON_AEAD_RATE == 16)
            {
                x1 ^= LOAD(m, mOff + 8, 8);
                STORE(c, cOff + 8, x1, 8);
            }
            P(nr);
            mOff += ASCON_AEAD_RATE;
            cOff += ASCON_AEAD_RATE;
            mlen -= ASCON_AEAD_RATE;
        }
    }

    private void ascon_decrypt(byte[] m, int mOff, byte[] c, int cOff, int clen)
    {
        /* full ciphertext blocks */
        while (clen >= ASCON_AEAD_RATE)
        {
            long cx = LOAD(c, cOff, 8);
            x0 ^= cx;
            STORE(m, mOff, x0, 8);
            x0 = cx;
            if (ASCON_AEAD_RATE == 16)
            {
                cx = LOAD(c, cOff + 8, 8);
                x1 ^= cx;
                STORE(m, mOff + 8, x1, 8);
                x1 = cx;
            }
            P(nr);
            mOff += ASCON_AEAD_RATE;
            cOff += ASCON_AEAD_RATE;
            clen -= ASCON_AEAD_RATE;
        }

    }

    private long CLEAR(long w, int n)
    {
        /* undefined for n == 0 */
        long mask = 0x00ffffffffffffffL >>> (n * 8 - 8);
        return w & mask;
    }

    private void ascon_final(byte[] c, int cOff, final byte[] m, int mOff, int mlen)
    {
        if (forEncryption)
        {
            /* final plaintext block */
            if (ASCON_AEAD_RATE == 16 && mlen >= 8)
            {
                x0 ^= LOAD(m, mOff, 8);
                STORE(c, cOff, x0, 8);
                mOff += 8;
                cOff += 8;
                mlen -= 8;
                x1 ^= PAD(mlen);
                if (mlen != 0)
                {
                    x1 ^= LOAD(m, mOff, mlen);
                    STORE(c, cOff, x1, mlen);
                }
            }
            else
            {
                x0 ^= PAD(mlen);
                if (mlen != 0)
                {
                    x0 ^= LOAD(m, mOff, mlen);
                    STORE(c, cOff, x0, mlen);
                }
            }
        }
        else
        {
            /* final ciphertext block */
            if (ASCON_AEAD_RATE == 16 && mlen >= 8)
            {
                long cx = LOAD(m, mOff, 8);
                x0 ^= cx;
                STORE(c, cOff, x0, 8);
                x0 = cx;
                mOff += 8;
                cOff += 8;
                mlen -= 8;
                x1 ^= PAD(mlen);
                if (mlen != 0)
                {
                    cx = LOAD(m, mOff, mlen);
                    x1 ^= cx;
                    STORE(c, cOff, x1, mlen);
                    x1 = CLEAR(x1, mlen);
                    x1 ^= cx;
                }
            }
            else
            {
                x0 ^= PAD(mlen);
                if (mlen != 0)
                {
                    long cx = LOAD(m, mOff, mlen);
                    x0 ^= cx;
                    STORE(c, cOff, x0, mlen);
                    x0 = CLEAR(x0, mlen);
                    x0 ^= cx;
                }
            }
        }

        /* finalize */
        switch (asconParameters)
        {
        case ascon128:
            x1 ^= K1;
            x2 ^= K2;
            break;
        case ascon128a:
            x2 ^= K1;
            x3 ^= K2;
            break;
        case ascon80pq:
            x1 ^= KEYROT(K0, K1);
            x2 ^= KEYROT(K1, K2);
            x3 ^= KEYROT(K2, 0L);
            break;
        }
        P(12);
        x3 ^= K1;
        x4 ^= K2;
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
            throw new IllegalArgumentException("ASCON init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV)params;
        byte[] npub = ivParams.getIV();
        if (npub == null || npub.length != CRYPTO_ABYTES)
        {
            throw new IllegalArgumentException(asconParameters + " requires exactly " + CRYPTO_ABYTES + " bytes of IV");
        }
        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "ASCON init parameters must include a key");
        }
        KeyParameter key = (KeyParameter)ivParams.getParameters();
        byte[] k = key.getKey();
        if (k.length != CRYPTO_KEYBYTES)
        {
            throw new IllegalArgumentException(asconParameters + " key must be " + CRYPTO_KEYBYTES + " bytes long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        N0 = LOAD(npub, 0, 8);
        N1 = LOAD(npub, 8, 8);
        if (CRYPTO_KEYBYTES == 16)
        {
            K1 = LOAD(k, 0, 8);
            K2 = LOAD(k, 8, 8);
        }
        else if (CRYPTO_KEYBYTES == 20)
        {
            K0 = KEYROT(0, LOADBYTES(k, 0, 4));
            K1 = LOADBYTES(k, 4, 8);
            K2 = LOADBYTES(k, 12, 8);
        }
        initialised = true;
        /*Mask-Gen*/
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public String getAlgorithmVersion()
    {
        return "v1.2";
    }

    @Override
    public void processAADByte(byte in)
    {
        if (aadFinished)
        {
            throw new IllegalArgumentException("AAD cannot be added after reading a full block(" + ASCON_AEAD_RATE +
                " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
        }
        aadData.write(in);
    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (aadFinished)
        {
            throw new IllegalArgumentException("AAD cannot be added after reading a full block(" + ASCON_AEAD_RATE +
                " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
        }
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short" + (forEncryption ? "encryption" : "decryption"));
        }
        aadData.write(in, inOff, len);
    }

    private void processAAD()
    {
        if (!aadFinished)
        {
            byte[] ad = aadData.toByteArray();
            int adlen = aadData.size();
            /* perform ascon computation */
            ascon_adata(ad, 0, adlen);
            aadFinished = true;
        }
    }

    private int processBytes(byte[] out, int outOff)
        throws OutputLengthException
    {
        int len = 0;
        if (forEncryption)
        {
            if (message.size() >= ASCON_AEAD_RATE)
            {
                processAAD();
                byte[] in = message.toByteArray();
                len = (in.length / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                if (len + outOff > out.length)
                {
                    throw new OutputLengthException("output buffer is too short");
                }
                ascon_encrypt(out, outOff, in, 0, len);
                message.reset();
                message.write(in, len, in.length - len);
            }
        }
        else
        {
            if (message.size() - CRYPTO_ABYTES >= ASCON_AEAD_RATE)
            {
                processAAD();
                byte[] in = message.toByteArray();
                len = ((in.length - CRYPTO_ABYTES) / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                if (len + outOff > out.length)
                {
                    throw new OutputLengthException("output buffer is too short");
                }
                ascon_decrypt(out, outOff, in, 0, len);
                message.reset();
                message.write(in, len, in.length - len);
            }
        }
        return len;
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{in}, 0, 1, out, outOff);
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        message.write(in, inOff, len);
        int rv = processBytes(out, outOff);
        encrypted = true;
        return rv;
    }

    @Override
    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException, DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        if (!aadFinished)
        {
            processAAD();
        }
        if (!encrypted)
        {
            processBytes(new byte[]{}, 0, 0, new byte[]{}, 0);
        }
        byte[] in = message.toByteArray();
        int len = in.length;
        if ((forEncryption && outOff + len + CRYPTO_ABYTES > out.length) ||
            (!forEncryption && outOff + len - CRYPTO_ABYTES > out.length))
        {
            throw new OutputLengthException("output buffer too short");
        }
        if (forEncryption)
        {
            ascon_final(out, outOff, in, 0, len);
            /* set tag */
            mac = new byte[16];
            STOREBYTES(mac, 0, x3, 8);
            STOREBYTES(mac, 8, x4, 8);
            System.arraycopy(mac, 0, out, len + outOff, 16);
            reset(false);
            return len + CRYPTO_ABYTES;
        }
        else
        {
            len -= CRYPTO_ABYTES;
            ascon_final(out, outOff, in, 0, len);
            x3 ^= LOADBYTES(in, len, 8);
            x4 ^= LOADBYTES(in, len + 8, 8);
            long result = x3 | x4;
            result |= result >>> 32;
            result |= result >>> 16;
            result |= result >>> 8;
            reset(true);
            if ((((((int)(result & 0xffL) - 1L) >>> 8) & 1) - 1) != 0)
            {
                throw new IllegalArgumentException("Mac does not match");
            }
            return len;
        }

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
        return len + CRYPTO_ABYTES;
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
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        x0 = x1 = x2 = x3 = x4 = 0;
        ascon_aeadinit();
        aadData.reset();
        message.reset();
        encrypted = false;
        aadFinished = false;
        if (clearMac)
        {
            mac = null;
        }
    }

    public int getKeyBytesSize()
    {
        return CRYPTO_KEYBYTES;
    }

    public int getIVBytesSize()
    {
        return CRYPTO_ABYTES;
    }
}


