package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Blake2spDigest
    implements ExtendedDigest
{
    private int bufferPos = 0; // a value from 0 up to BLOCK_LENGTH_BYTES

    private int keyLength = 0; // 0 - 32 bytes
    private int digestLength; // 0 - 32 bytes
    private int fanout; // 0-255
    private int depth; // 0-255

    private int nodeOffset = 0;
    private long innerHashLength;

    private Blake2sDigest[] S = new Blake2sDigest[8];
    private Blake2sDigest root;

    private byte[] buffer = null;

    private byte[] salt = null;
    private byte[] param = null;
    private byte[] key = null;
    private final int BLAKE2S_BLOCKBYTES = 64;
    private final int BLAKE2S_KEYBYTES = 32;
    private final int BLAKE2S_OUTBYTES = 32;
    private final int PARALLELISM_DEGREE = 8;

    private final byte[] singleByte = new byte[1];


    public Blake2spDigest(byte[] key)
    {
        param = new byte[32];
        buffer = new byte[8 * BLAKE2S_BLOCKBYTES];
        init(key);
    }


    @Override
    public String getAlgorithmName()
    {
        return "BLAKE2sp";
    }

    @Override
    public int getDigestSize()
    {
        return digestLength;
    }

    @Override
    public void update(byte in)
    {
        singleByte[0] = in;
        update(singleByte, 0, 1);
    }

    @Override
    public void update(byte[] message, int offset, int len)
    {
        int left = bufferPos;
        int remainingLength = 8*BLAKE2S_BLOCKBYTES - left;

        if(left != 0 && len >= remainingLength)
        {
            System.arraycopy(message, offset, buffer, left, remainingLength);

            for (int i = 0; i < PARALLELISM_DEGREE; i++)
            {
                S[i].update(buffer, i * BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES);
            }
            offset += remainingLength;
            len -= remainingLength;
            left = 0;
        }

        //TODO: make threads run each iteration
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            int inlen = len;
            int inOffset = offset;
            inOffset += i * BLAKE2S_BLOCKBYTES;

            while (inlen >= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES)
            {
                S[i].update(message, inOffset, BLAKE2S_BLOCKBYTES);
                inOffset += PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
                inlen -= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
            }
        }

        offset += len - len % ( PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES );
        len %= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;

        if(len > 0)
        {
            System.arraycopy(message, offset, buffer, left, len);
        }

        bufferPos = left + len;
    }

    @Override
    public int doFinal(byte[] out, int outOff)
    {
        byte[][] hash = new byte[PARALLELISM_DEGREE][BLAKE2S_OUTBYTES];

        int remainingLength = 0; // left bytes of buffer

        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            if (bufferPos > i * BLAKE2S_BLOCKBYTES)
            {
                remainingLength = bufferPos - i * BLAKE2S_BLOCKBYTES;

                if (remainingLength > BLAKE2S_BLOCKBYTES)
                {
                    remainingLength = BLAKE2S_BLOCKBYTES;
                }

                S[i].update(buffer, i * BLAKE2S_BLOCKBYTES, remainingLength);
            }

            S[i].doFinal(hash[i], 0);
        }

        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            root.update(hash[i], 0, BLAKE2S_OUTBYTES);
        }
        int length = root.doFinal(out, outOff);

        reset();

        return length;
    }

    @Override
    public void reset()
    {
        bufferPos = 0;
        digestLength = 32;
        // init root
        root.reset();
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            S[i].reset();
        }

        root.setAsLastNode();
        S[PARALLELISM_DEGREE-1].setAsLastNode();

        if(key != null)
        {
            byte[] block = new byte[BLAKE2S_BLOCKBYTES];
            System.arraycopy(key, 0, block, 0, keyLength);
            for (int i = 0; i < PARALLELISM_DEGREE; i++)
            {
                S[i].update(block, 0, BLAKE2S_BLOCKBYTES);
            }
        }
    }

    @Override
    public int getByteLength()
    {
        return BLAKE2S_BLOCKBYTES;
    }

    // initializes parameters
    private void init(byte[] key)
    {
        if (key != null && key.length > 0)
        {
            keyLength = key.length;
            if (keyLength > BLAKE2S_KEYBYTES)
            {
                throw new IllegalArgumentException("Keys > 32 bytes are not supported");
            }
            this.key = Arrays.clone(key);
        }

        bufferPos = 0;
        digestLength = 32;

        // init root
        fanout = PARALLELISM_DEGREE;
        depth = 2;
        innerHashLength = BLAKE2S_OUTBYTES;

        param[0] = (byte) digestLength;
        param[1] = (byte) keyLength;
        param[2] = (byte) fanout;
        param[3] = (byte) depth;
        Pack.intToLittleEndian(0, param, 8);
        param[14] = 1; // node depth
        param[15] = (byte) innerHashLength;

        root = new Blake2sDigest(null, param);

        // init leaf
//        param[0] = (byte) digestLength;
        Pack.intToLittleEndian(nodeOffset, param, 8);
        param[14] = 0;  // node depth
        for (int i = 0; i < PARALLELISM_DEGREE; i++)
        {
            Pack.intToLittleEndian(i, param, 8);
            S[i] = new Blake2sDigest(null, param);
        }

        root.setAsLastNode();
        S[PARALLELISM_DEGREE-1].setAsLastNode();

        if(key != null && keyLength > 0)
        {
            byte[] block = new byte[BLAKE2S_BLOCKBYTES];
            System.arraycopy(key, 0, block, 0, keyLength);
            for (int i = 0; i < PARALLELISM_DEGREE; i++)
            {
                S[i].update(block, 0, BLAKE2S_BLOCKBYTES);
            }
        }
    }
}
