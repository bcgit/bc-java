package org.bouncycastle.pqc.crypto.mayo;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class MayoEngine
{
    /**
     * Expands P1 and P2 using AES_128_CTR as a PRF and then unpacks the resulting bytes
     * into an array of 64-bit limbs.
     *
     * @param p       Mayo parameters
     * @param P       The output long array which will hold the unpacked limbs.
     *                Its length should be at least ((P1_bytes + P2_bytes) / 8) limbs.
     * @param seed_pk The seed (used as the key) for the PRF.
     * @return The number of bytes produced, i.e., P1_bytes + P2_bytes.
     */
    public static int expandP1P2(MayoParameters p, long[] P, byte[] seed_pk)
    {
        // Compute total number of bytes to generate: P1_bytes + P2_bytes.
        int outLen = p.getP1Bytes() + p.getP2Bytes();
        // Temporary byte array to hold the PRF output.
        byte[] temp = new byte[outLen];

        // Call AES_128_CTR (our previously defined function using BouncyCastle)
        // to fill temp with outLen pseudorandom bytes using seed_pk as key.
        AES_128_CTR(temp, outLen, seed_pk, p.getPkSeedBytes());

        // The number of vectors is the total limbs divided by mVecLimbs.
        int numVectors = (p.getP1Limbs() + p.getP2Limbs()) / p.getMVecLimbs();

        // Unpack the byte array 'temp' into the long array 'P'
        // using our previously defined unpackMVecs method.
        Utils.unpackMVecs(temp, P, numVectors, p.getM());

        // Return the number of output bytes produced.
        return outLen;
    }

    /**
     * AES_128_CTR generates outputByteLen bytes using AES-128 in CTR mode.
     * The key (of length keyLen) is used to expand the AES key.
     * A 16-byte IV (all zeros) is used.
     *
     * @param output        the output buffer which will be filled with the keystream
     * @param outputByteLen the number of bytes to produce
     * @param key           the AES key (should be 16 bytes for AES-128)
     * @param keyLen        the length of the key (unused here but kept for similarity)
     * @return the number of output bytes produced (i.e. outputByteLen)
     */
    public static int AES_128_CTR(byte[] output, int outputByteLen, byte[] key, int keyLen)
    {
        // Create a 16-byte IV (all zeros)
        byte[] iv = new byte[16]; // automatically zero-initialized

        // Set up AES engine in CTR (SIC) mode.
        BlockCipher aesEngine = AESEngine.newInstance();
        // SICBlockCipher implements CTR mode for AES.
        CTRModeCipher ctrCipher = SICBlockCipher.newInstance(aesEngine);
        // Wrap the key with the IV.
        ParametersWithIV params = new ParametersWithIV(new KeyParameter(Arrays.copyOf(key, keyLen)), iv);
        ctrCipher.init(true, params);

        // CTR mode is a stream cipher: encrypting zero bytes produces the keystream.
        int blockSize = ctrCipher.getBlockSize(); // typically 16 bytes
        byte[] zeroBlock = new byte[blockSize];     // block of zeros
        byte[] blockOut = new byte[blockSize];

        int offset = 0;
        // Process full blocks
        while (offset + blockSize <= outputByteLen)
        {
            ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
            System.arraycopy(blockOut, 0, output, offset, blockSize);
            offset += blockSize;
        }
        // Process any remaining partial block.
        if (offset < outputByteLen)
        {
            ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
            int remaining = outputByteLen - offset;
            System.arraycopy(blockOut, 0, output, offset, remaining);
        }
        return outputByteLen;
    }

    public static final int MAYO_OK = 0;
    public static final int PK_SEED_BYTES_MAX = 16;  // Adjust as needed
    public static final int O_BYTES_MAX = 312;         // Adjust as needed

    /**
     * Expands the secret key.
     *
     * @param p   the MayoParameters instance.
     * @param csk the input secret key seed (byte array).
     * @param sk  the Sk object that holds the expanded secret key components.
     * @return MAYO_OK on success.
     */
//    public static int mayoExpandSk(MayoParameters p, byte[] csk, MayoPrivateKeyParameter sk)
//    {
//        int ret = MAYO_OK;
//        int totalS = PK_SEED_BYTES_MAX + O_BYTES_MAX;
//        byte[] S = new byte[totalS];
//
//        // sk.p is the long[] array, sk.O is the byte[] array.
//
//        long[] P = new long[p.getPkSeedBytes() >> 3];
//        Pack.littleEndianToLong(sk.getP(), 0, P);
//        byte[] O = sk.getO();
//
//        int param_o = p.getO();
//        int param_v = p.getV();
//        int param_O_bytes = p.getOBytes();
//        int param_pk_seed_bytes = p.getPkSeedBytes();
//        int param_sk_seed_bytes = p.getSkSeedBytes();
//
//        // In C, seed_sk = csk and seed_pk = S (the beginning of S)
//        byte[] seed_sk = csk;
//        byte[] seed_pk = S;  // first param_pk_seed_bytes of S
//
//        // Generate S = seed_pk || (additional bytes), using SHAKE256.
//        // Output length is param_pk_seed_bytes + param_O_bytes.
//        Utils.shake256(S, param_pk_seed_bytes + param_O_bytes, seed_sk, param_sk_seed_bytes);
//
//        // Decode the portion of S after the first param_pk_seed_bytes into O.
//        // (In C, this is: decode(S + param_pk_seed_bytes, O, param_v * param_o))
//        Utils.decode(S, param_pk_seed_bytes, O, param_v * param_o);
//
//        // Expand P1 and P2 into the long array P using seed_pk.
//        MayoEngine.expandP1P2(p, P, seed_pk);
//
//        // Let P2 start at offset = PARAM_P1_limbs(p)
//        int p1Limbs = p.getP1Limbs();
//        int offsetP2 = p1Limbs;
//
//        // Compute L_i = (P1 + P1^t)*O + P2.
//        // Here, we assume that P1P1tTimesO writes into the portion of P starting at offsetP2.
//        P1P1tTimesO(p, P, O, P, offsetP2);
//
//        // Securely clear sensitive temporary data.
//        java.util.Arrays.fill(S, (byte)0);
//        return ret;
//    }

    /**
     * Multiplies and accumulates the product (P1 + P1^t)*O into the accumulator.
     * This version writes into the 'acc' array starting at the specified offset.
     *
     * @param p         the MayoParameters.
     * @param P1        the P1 vector as a long[] array.
     * @param O         the O array (each byte represents a GF(16) element).
     * @param acc       the accumulator array where results are XORed in.
     * @param accOffset the starting index in acc.
     */
    public static void P1P1tTimesO(MayoParameters p, long[] P1, byte[] O, long[] acc, int accOffset)
    {
        int paramO = p.getO();
        int paramV = p.getV();
        int mVecLimbs = p.getMVecLimbs();
        int bsMatEntriesUsed = 0;
        for (int r = 0; r < paramV; r++)
        {
            for (int c = r; c < paramV; c++)
            {
                if (c == r)
                {
                    bsMatEntriesUsed++;
                    continue;
                }
                for (int k = 0; k < paramO; k++)
                {
                    // Multiply the m-vector at P1 for the current matrix entry,
                    // and accumulate into acc for row r.
                    GF16Utils.mVecMulAdd(mVecLimbs, P1, bsMatEntriesUsed * mVecLimbs,
                        O[c * paramO + k] & 0xFF, acc, accOffset + (r * paramO + k) * mVecLimbs);
                    // Similarly, accumulate into acc for row c.
                    GF16Utils.mVecMulAdd(mVecLimbs, P1, bsMatEntriesUsed * mVecLimbs,
                        O[r * paramO + k] & 0xFF, acc, accOffset + (c * paramO + k) * mVecLimbs);
                }
                bsMatEntriesUsed++;
            }
        }
    }
}
