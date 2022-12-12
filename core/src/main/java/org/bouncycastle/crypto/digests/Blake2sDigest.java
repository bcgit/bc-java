package org.bouncycastle.crypto.digests;

/*
  The BLAKE2 cryptographic hash function was designed by Jean-
  Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
  Winnerlein.

  Reference Implementation and Description can be found at: https://blake2.net/
  RFC: https://tools.ietf.org/html/rfc7693

  This implementation does not support the Tree Hashing Mode.

  For unkeyed hashing, developers adapting BLAKE2 to ASN.1 - based
  message formats SHOULD use the OID tree at x = 1.3.6.1.4.1.1722.12.2.

         Algorithm     | Target | Collision | Hash | Hash ASN.1 |
            Identifier |  Arch  |  Security |  nn  | OID Suffix |
        ---------------+--------+-----------+------+------------+
         id-blake2s128 | 32-bit |   2**64   |  16  |   x.2.4    |
         id-blake2s160 | 32-bit |   2**80   |  20  |   x.2.5    |
         id-blake2s224 | 32-bit |   2**112  |  28  |   x.2.7    |
         id-blake2s256 | 32-bit |   2**128  |  32  |   x.2.8    |
        ---------------+--------+-----------+------+------------+
 */

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Implementation of the cryptographic hash function BLAKE2s.
 * <p/>
 * BLAKE2s offers a built-in keying mechanism to be used directly
 * for authentication ("Prefix-MAC") rather than a HMAC construction.
 * <p/>
 * BLAKE2s offers a built-in support for a salt for randomized hashing
 * and a personal string for defining a unique hash function for each application.
 * <p/>
 * BLAKE2s is optimized for 32-bit platforms and produces digests of any size
 * between 1 and 32 bytes.
 */
public class Blake2sDigest
    implements ExtendedDigest
{
    /**
     * BLAKE2s Initialization Vector
     **/
    private static final int[] blake2s_IV =
        // Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
        // The same as SHA-256 IV.
        {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372,
            0xa54ff53a, 0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
        };

    /**
     * Message word permutations
     **/
    private static final byte[][] blake2s_sigma =
        {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
        };

    private static final int ROUNDS = 10; // to use for Catenas H'
    private static final int BLOCK_LENGTH_BYTES = 64;// bytes

    // General parameters:
    private int digestLength = 32; // 1- 32 bytes
    private int keyLength = 0; // 0 - 32 bytes for keyed hashing for MAC
    private byte[] salt = null;
    private byte[] personalization = null;
    private byte[] key = null;

    // Tree hashing parameters:
    // The Tree Hashing Mode is not supported but these are used for
    // the XOF implementation
    private int fanout = 1; // 0-255
    private int depth = 1; // 0-255
    private int leafLength = 0;
    private long nodeOffset = 0L;
    private int nodeDepth = 0;
    private int innerHashLength = 0;

    private boolean isLastNode = false;


    /**
     * Whenever this buffer overflows, it will be processed in the compress()
     * function. For performance issues, long messages will not use this buffer.
     */
    private byte[] buffer = null;
    /**
     * Position of last inserted byte
     **/
    private int bufferPos = 0;// a value from 0 up to BLOCK_LENGTH_BYTES

    /**
     * Internal state, in the BLAKE2 paper it is called v
     **/
    private int[] internalState = new int[16];
    /**
     * State vector, in the BLAKE2 paper it is called h
     **/
    private int[] chainValue = null;

    // counter (counts bytes): Length up to 2^64 are supported
    /**
     * holds least significant bits of counter
     **/
    private int t0 = 0;
    /**
     * holds most significant bits of counter
     **/
    private int t1 = 0;
    /**
     * finalization flag, for last block: ~0
     **/
    private int f0 = 0;

    // For Tree Hashing Mode, not used here:
     private int f1 = 0;
    // finalization flag, for last node: ~0L

    // digest purpose
    private final CryptoServicePurpose purpose;

    /**
     * BLAKE2s-256 for hashing.
     */
    public Blake2sDigest()
    {
        this(256, CryptoServicePurpose.ANY);
    }

    /**
     * Basic sized constructor - size in bits.
     *
     * @param digestSize size of digest (in bits)
     */
    public Blake2sDigest(int digestSize)
    {
        this(digestSize, CryptoServicePurpose.ANY);
    }

    public Blake2sDigest(Blake2sDigest digest)
    {
        this.bufferPos = digest.bufferPos;
        this.buffer = Arrays.clone(digest.buffer);
        this.keyLength = digest.keyLength;
        this.key = Arrays.clone(digest.key);
        this.digestLength = digest.digestLength;
        this.internalState = Arrays.clone(digest.internalState);
        this.chainValue = Arrays.clone(digest.chainValue);
        this.t0 = digest.t0;
        this.t1 = digest.t1;
        this.f0 = digest.f0;
        this.salt = Arrays.clone(digest.salt);
        this.personalization = Arrays.clone(digest.personalization);
        this.fanout = digest.fanout;
        this.depth = digest.depth;
        this.leafLength = digest.leafLength;
        this.nodeOffset = digest.nodeOffset;
        this.nodeDepth = digest.nodeDepth;
        this.innerHashLength = digest.innerHashLength;
        this.purpose = digest.purpose;
    }

    /**
     * BLAKE2s for hashing.
     *
     * @param digestBits the desired digest length in bits. Must be a multiple of 8 and less than 256.
     * @param purpose usage purpose.
     */
    public Blake2sDigest(int digestBits, CryptoServicePurpose purpose)
    {
        if (digestBits < 8 || digestBits > 256 || digestBits % 8 != 0)
        {
            throw new IllegalArgumentException(
                "BLAKE2s digest bit length must be a multiple of 8 and not greater than 256");
        }
        digestLength = digestBits / 8;
        this.purpose = purpose;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, digestBits, purpose));
        init(null, null, null);
    }

    /**
     * BLAKE2s for authentication ("Prefix-MAC mode").
     * <p/>
     * After calling the doFinal() method, the key will remain to be used for
     * further computations of this instance. The key can be overwritten using
     * the clearKey() method.
     *
     * @param key a key up to 32 bytes or null
     */
    public Blake2sDigest(byte[] key)
    {
        this(key, CryptoServicePurpose.ANY);
    }

    public Blake2sDigest(byte[] key, CryptoServicePurpose purpose)
    {
        this.purpose = purpose;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, key.length*8, purpose));
        init(null, null, key);
    }

    /**
     * BLAKE2s with key, required digest length, salt and personalization.
     * <p/>
     * After calling the doFinal() method, the key, the salt and the personal
     * string will remain and might be used for further computations with this
     * instance. The key can be overwritten using the clearKey() method, the
     * salt (pepper) can be overwritten using the clearSalt() method.
     *
     * @param key             a key up to 32 bytes or null
     * @param digestBytes     from 1 up to 32 bytes
     * @param salt            8 bytes or null
     * @param personalization 8 bytes or null
     */
    public Blake2sDigest(byte[] key, int digestBytes, byte[] salt,
                         byte[] personalization)
    {
        this(key, digestBytes, salt, personalization, CryptoServicePurpose.ANY);
    }
    public Blake2sDigest(byte[] key, int digestBytes, byte[] salt,
                         byte[] personalization, CryptoServicePurpose purpose)
    {
        if (digestBytes < 1 || digestBytes > 32)
        {
            throw new IllegalArgumentException(
                "Invalid digest length (required: 1 - 32)");
        }
        digestLength = digestBytes;
        this.purpose = purpose;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, digestBytes*8, purpose));
        init(salt, personalization, key);
    }

    // XOF root hash parameters
    Blake2sDigest(int digestBytes, byte[] key, byte[] salt, byte[] personalization, long offset, CryptoServicePurpose purpose)
    {
        digestLength = digestBytes;
        nodeOffset = offset;
        this.purpose = purpose;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, digestBytes*8, purpose));
        init(salt, personalization, key);
    }

    // XOF internal hash parameters
    Blake2sDigest(int digestBytes, int hashLength, long offset)
    {
        this(digestBytes, hashLength, offset, CryptoServicePurpose.ANY);
    }
    Blake2sDigest(int digestBytes, int hashLength, long offset, CryptoServicePurpose purpose)
    {
        digestLength = digestBytes;
        nodeOffset = offset;
        fanout = 0;
        depth = 0;
        leafLength = hashLength;
        innerHashLength = hashLength;
        nodeDepth = 0;
        this.purpose = purpose;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, digestBytes*8, purpose));
        init(null, null, null);
    }
    Blake2sDigest (byte[] key, byte[] param)
    {
        this.purpose = CryptoServicePurpose.ANY;
        digestLength = param[0];
        keyLength = param[1];
        fanout = param[2];
        depth = param[3];
        leafLength = Pack.littleEndianToInt(param, 4);
        nodeOffset |= Pack.littleEndianToInt(param, 8);
        //xoflength
        nodeDepth = param[14];
        innerHashLength = param[15];
        byte[] salt = new byte[8];
        byte[] personalization = new byte[8];
        System.arraycopy(param, 16, salt, 0, 8);
        System.arraycopy(param, 24, personalization, 0, 8);
        init(salt, personalization, key);
    }

    // initialize the digest's parameters
    private void init(byte[] salt, byte[] personalization, byte[] key)
    {
        buffer = new byte[BLOCK_LENGTH_BYTES];

        if (key != null && key.length > 0)
        {
            keyLength = key.length;
            if (keyLength > 32)
            {
                throw new IllegalArgumentException("Keys > 32 bytes are not supported");
            }
            this.key = new byte[keyLength];
            System.arraycopy(key, 0, this.key, 0, keyLength);
            System.arraycopy(key, 0, buffer, 0, keyLength);
            bufferPos = BLOCK_LENGTH_BYTES; // zero padding
        }

        if (chainValue == null)
        {
            chainValue = new int[8];

            chainValue[0] = blake2s_IV[0] ^ (digestLength | (keyLength << 8) | ((fanout << 16) | (depth << 24)));
            chainValue[1] = blake2s_IV[1] ^ leafLength;

            int nofHi = (int)(nodeOffset >> 32);
            int nofLo = (int)nodeOffset;
            chainValue[2] = blake2s_IV[2] ^ nofLo;
            chainValue[3] = blake2s_IV[3] ^ (nofHi | (nodeDepth << 16) | (innerHashLength << 24));

            chainValue[4] = blake2s_IV[4];
            chainValue[5] = blake2s_IV[5];
            if (salt != null)
            {
                if (salt.length != 8)
                {
                    throw new IllegalArgumentException("Salt length must be exactly 8 bytes");
                }
                this.salt = new byte[8];
                System.arraycopy(salt, 0, this.salt, 0, salt.length);

                chainValue[4] ^= Pack.littleEndianToInt(salt, 0);
                chainValue[5] ^= Pack.littleEndianToInt(salt, 4);
            }

            chainValue[6] = blake2s_IV[6];
            chainValue[7] = blake2s_IV[7];
            if (personalization != null)
            {
                if (personalization.length != 8)
                {
                    throw new IllegalArgumentException("Personalization length must be exactly 8 bytes");
                }
                this.personalization = new byte[8];
                System.arraycopy(personalization, 0, this.personalization, 0, personalization.length);

                chainValue[6] ^= Pack.littleEndianToInt(personalization, 0);
                chainValue[7] ^= Pack.littleEndianToInt(personalization, 4);
            }
        }
    }

    private void initializeInternalState()
    {
        // initialize v:
        System.arraycopy(chainValue, 0, internalState, 0, chainValue.length);
        System.arraycopy(blake2s_IV, 0, internalState, chainValue.length, 4);
        internalState[12] = t0 ^ blake2s_IV[4];
        internalState[13] = t1 ^ blake2s_IV[5];
        internalState[14] = f0 ^ blake2s_IV[6];
        internalState[15] = f1 ^ blake2s_IV[7];
    }

    /**
     * Update the message digest with a single byte.
     *
     * @param b the input byte to be entered.
     */
    public void update(byte b)
    {
        int remainingLength; // left bytes of buffer

        // process the buffer if full else add to buffer:
        remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
        if (remainingLength == 0)
        { // full buffer
            t0 += BLOCK_LENGTH_BYTES;
            if (t0 == 0)
            { // if message > 2^32
                t1++;
            }
            compress(buffer, 0);
            Arrays.fill(buffer, (byte)0);// clear buffer
            buffer[0] = b;
            bufferPos = 1;
        }
        else
        {
            buffer[bufferPos] = b;
            bufferPos++;
        }
    }

    /**
     * Update the message digest with a block of bytes.
     *
     * @param message the byte array containing the data.
     * @param offset  the offset into the byte array where the data starts.
     * @param len     the length of the data.
     */
    public void update(byte[] message, int offset, int len)
    {
        if (message == null || len == 0)
        {
            return;
        }

        int remainingLength = 0; // left bytes of buffer

        if (bufferPos != 0)
        { // commenced, incomplete buffer

            // complete the buffer:
            remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
            if (remainingLength < len)
            { // full buffer + at least 1 byte
                System.arraycopy(message, offset, buffer, bufferPos,
                    remainingLength);
                t0 += BLOCK_LENGTH_BYTES;
                if (t0 == 0)
                { // if message > 2^32
                    t1++;
                }
                compress(buffer, 0);
                bufferPos = 0;
                Arrays.fill(buffer, (byte)0);// clear buffer
            }
            else
            {
                System.arraycopy(message, offset, buffer, bufferPos, len);
                bufferPos += len;
                return;
            }
        }

        // process blocks except last block (also if last block is full)
        int messagePos;
        int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;
        for (messagePos = offset + remainingLength;
             messagePos < blockWiseLastPos;
             messagePos += BLOCK_LENGTH_BYTES)
        { // block wise 64 bytes
            // without buffer:
            t0 += BLOCK_LENGTH_BYTES;
            if (t0 == 0)
            {
                t1++;
            }
            compress(message, messagePos);
        }

        // fill the buffer with left bytes, this might be a full block
        System.arraycopy(message, messagePos, buffer, 0, offset + len
            - messagePos);
        bufferPos += offset + len - messagePos;
    }

    /**
     * Close the digest, producing the final digest value. The doFinal() call
     * leaves the digest reset. Key, salt and personal string remain.
     *
     * @param out       the array the digest is to be copied into.
     * @param outOffset the offset into the out array the digest is to start at.
     */
    public int doFinal(byte[] out, int outOffset)
    {
        if (outOffset > (out.length - digestLength))
        {
            throw new OutputLengthException("output buffer too short");
        }

        f0 = 0xFFFFFFFF;
        if(isLastNode)
        {
            f1 = 0xFFFFFFFF;
        }
        t0 += bufferPos;
        // bufferPos may be < 64, so (t0 == 0) does not work
        // for 2^32 < message length > 2^32 - 63
        if ((t0 < 0) && (bufferPos > -t0))
        {
            t1++;
        }
        compress(buffer, 0);
        Arrays.fill(buffer, (byte)0);// Holds eventually the key if input is null
        Arrays.fill(internalState, 0);

        int full = digestLength >>> 2, partial = digestLength & 3;
        Pack.intToLittleEndian(chainValue, 0, full, out, outOffset);
        if (partial > 0)
        {
            byte[] bytes = new byte[4];
            Pack.intToLittleEndian(chainValue[full], bytes, 0);
            System.arraycopy(bytes, 0, out, outOffset + digestLength - partial, partial);
        }

        Arrays.fill(chainValue, 0);

        reset();

        return digestLength;
    }

    /**
     * Reset the digest back to its initial state. The key, the salt and the
     * personal string will remain for further computations.
     */
    public void reset()
    {
        bufferPos = 0;
        f0 = 0;
        f1 = 0;
        t0 = 0;
        t1 = 0;
        isLastNode = false;
        chainValue = null;
        Arrays.fill(buffer, (byte)0);
        if (key != null)
        {
            System.arraycopy(key, 0, buffer, 0, key.length);
            bufferPos = BLOCK_LENGTH_BYTES; // zero padding
        }

        init(this.salt, this.personalization, this.key);
    }

    private void compress(byte[] message, int messagePos)
    {
        initializeInternalState();

        int[] m = new int[16];
        Pack.littleEndianToInt(message, messagePos, m);

        for (int round = 0; round < ROUNDS; round++)
        {
            // G apply to columns of internalState:m[blake2s_sigma[round][2 *
            // blockPos]] /+1
            G(m[blake2s_sigma[round][0]], m[blake2s_sigma[round][1]], 0, 4, 8, 12);
            G(m[blake2s_sigma[round][2]], m[blake2s_sigma[round][3]], 1, 5, 9, 13);
            G(m[blake2s_sigma[round][4]], m[blake2s_sigma[round][5]], 2, 6, 10, 14);
            G(m[blake2s_sigma[round][6]], m[blake2s_sigma[round][7]], 3, 7, 11, 15);
            // G apply to diagonals of internalState:
            G(m[blake2s_sigma[round][8]], m[blake2s_sigma[round][9]], 0, 5, 10, 15);
            G(m[blake2s_sigma[round][10]], m[blake2s_sigma[round][11]], 1, 6, 11, 12);
            G(m[blake2s_sigma[round][12]], m[blake2s_sigma[round][13]], 2, 7, 8, 13);
            G(m[blake2s_sigma[round][14]], m[blake2s_sigma[round][15]], 3, 4, 9, 14);
        }

        // update chain values:
        for (int offset = 0; offset < chainValue.length; offset++)
        {
            chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
        }
    }

    private void G(int m1, int m2, int posA, int posB, int posC, int posD)
    {
        internalState[posA] = internalState[posA] + internalState[posB] + m1;
        internalState[posD] = Integers.rotateRight(internalState[posD] ^ internalState[posA], 16);
        internalState[posC] = internalState[posC] + internalState[posD];
        internalState[posB] = Integers.rotateRight(internalState[posB] ^ internalState[posC], 12);
        internalState[posA] = internalState[posA] + internalState[posB] + m2;
        internalState[posD] = Integers.rotateRight(internalState[posD] ^ internalState[posA], 8);
        internalState[posC] = internalState[posC] + internalState[posD];
        internalState[posB] = Integers.rotateRight(internalState[posB] ^ internalState[posC], 7);
    }

    protected void setAsLastNode()
    {
        isLastNode = true;
    }

    /**
     * Return the algorithm name.
     *
     * @return the algorithm name
     */
    public String getAlgorithmName()
    {
        return "BLAKE2s";
    }

    /**
     * Return the size in bytes of the digest produced by this message digest.
     *
     * @return the size in bytes of the digest produced by this message digest.
     */
    public int getDigestSize()
    {
        return digestLength;
    }

    /**
     * Return the size in bytes of the internal buffer the digest applies its
     * compression function to.
     *
     * @return byte length of the digest's internal buffer.
     */
    public int getByteLength()
    {
        return BLOCK_LENGTH_BYTES;
    }

    /**
     * Overwrite the key if it is no longer used (zeroization).
     */
    public void clearKey()
    {
        if (key != null)
        {
            Arrays.fill(key, (byte)0);
            Arrays.fill(buffer, (byte)0);
        }
    }

    /**
     * Overwrite the salt (pepper) if it is secret and no longer used
     * (zeroization).
     */
    public void clearSalt()
    {
        if (salt != null)
        {
            Arrays.fill(salt, (byte)0);
        }
    }
}
