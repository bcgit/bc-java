package org.bouncycastle.pqc.crypto.picnic;

import java.security.SecureRandom;
import java.util.logging.Logger;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.raw.Bits;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

class PicnicEngine
{
    private static final Logger LOG = Logger.getLogger(PicnicEngine.class.getName());

    // same for all parameter sets
    protected static final int saltSizeBytes = 32;
    private static final int MAX_DIGEST_SIZE = 64;

    private static final int WORD_SIZE_BITS = 32;// the word size for the implementation. Not a LowMC parameter
    private static final int LOWMC_MAX_STATE_SIZE = 64;
    protected static final int LOWMC_MAX_WORDS = (LOWMC_MAX_STATE_SIZE / 4);
    protected static final int LOWMC_MAX_KEY_BITS = 256;
    protected static final int LOWMC_MAX_AND_GATES = (3 * 38 * 10 + 4);   /* Rounded to nearest byte */
    private static final int MAX_AUX_BYTES = ((LOWMC_MAX_AND_GATES + LOWMC_MAX_KEY_BITS) / 8 + 1);

    /* Maximum lengths in bytes */
    private static final int PICNIC_MAX_LOWMC_BLOCK_SIZE = 32;
//    private static final int PICNIC_MAX_PUBLICKEY_SIZE = (2 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 1);
    /**
     * < Largest serialized public key size, in bytes
     */
//    private static final int PICNIC_MAX_PRIVATEKEY_SIZE = (3 * PICNIC_MAX_LOWMC_BLOCK_SIZE + 2);
    /**
     * < Largest serialized private key size, in bytes
     */
//    private static final int PICNIC_MAX_SIGNATURE_SIZE = 209522;
    /**
     * < Largest signature size, in bytes
     */

    private static final int TRANSFORM_FS = 0;
    private static final int TRANSFORM_UR = 1;
    private static final int TRANSFORM_INVALID = 255;

    /// parameters
    private final int CRYPTO_SECRETKEYBYTES;
    private final int CRYPTO_PUBLICKEYBYTES;
    private final int CRYPTO_BYTES;

    // varies between parameter sets
    protected final int numRounds;
    protected final int numSboxes;
    protected final int stateSizeBits;
    protected final int stateSizeBytes;
    protected final int stateSizeWords;
    protected final int andSizeBytes;
    protected final int UnruhGWithoutInputBytes;
    protected final int UnruhGWithInputBytes;
    protected final int numMPCRounds;          // T
    protected final int numOpenedRounds;       // u
    protected final int numMPCParties;         // N
    protected final int seedSizeBytes;
    protected final int digestSizeBytes;
    protected final int pqSecurityLevel;

    protected final Xof digest;

    ///
    private final int transform;
    private final int parameters;
    private int signatureLength;

    public int getSecretKeySize()
    {
        return CRYPTO_SECRETKEYBYTES;
    }

    public int getPublicKeySize()
    {
        return CRYPTO_PUBLICKEYBYTES;
    }
    public int getSignatureSize(int messageLength)
    {
        return CRYPTO_BYTES + messageLength;
    }

    public int getTrueSignatureSize()
    {
        return signatureLength;
    }

    protected final LowmcConstants lowmcConstants;
    
    PicnicEngine(int picnicParams, LowmcConstants lowmcConstants)
    {
        this.lowmcConstants = lowmcConstants;
        parameters = picnicParams;
        switch (parameters)
        {
            case 1:
            case 2:
                /*Picnic_L1_FS
                  Picnic_L1_UR*/
                pqSecurityLevel = 64;
                stateSizeBits = 128;
                numMPCRounds = 219;
                numMPCParties = 3;
                numSboxes = 10;
                numRounds = 20;
                digestSizeBytes = 32;
                numOpenedRounds = 0;
                break;
            case 3:
            case 4:
                /* Picnic_L3_FS
                   Picnic_L3_UR*/
                pqSecurityLevel = 96;
                stateSizeBits = 192;
                numMPCRounds = 329;
                numMPCParties = 3;
                numSboxes = 10;
                numRounds = 30;
                digestSizeBytes = 48;
                numOpenedRounds = 0;
                break;
            case 5:
            case 6:
                /* Picnic_L5_FS
                   Picnic_L5_UR*/
                pqSecurityLevel = 128;
                stateSizeBits = 256;
                numMPCRounds = 438;
                numMPCParties = 3;
                numSboxes = 10;
                numRounds = 38;
                digestSizeBytes = 64;
                numOpenedRounds = 0;
                break;
            case 7:
                /*Picnic3_L1*/
                pqSecurityLevel = 64;
                stateSizeBits = 129;
                numMPCRounds = 250;
                numOpenedRounds = 36;
                numMPCParties = 16;
                numSboxes = 43;
                numRounds = 4;
                digestSizeBytes = 32;
                break;
            case 8:
                /*Picnic3_L3*/
                pqSecurityLevel = 96;
                stateSizeBits = 192;
                numMPCRounds = 419;
                numOpenedRounds = 52;
                numMPCParties = 16;
                numSboxes = 64;
                numRounds = 4;
                digestSizeBytes = 48;
                break;
            case 9:
                /*Picnic3_L5*/
                pqSecurityLevel = 128;
                stateSizeBits = 255;
                numMPCRounds = 601;
                numOpenedRounds = 68;
                numMPCParties = 16;
                numSboxes = 85;
                numRounds = 4;
                digestSizeBytes = 64;
                break;
            case 10:
                /*Picnic_L1_full*/
                pqSecurityLevel = 64;
                stateSizeBits = 129;
                numMPCRounds = 219;
                numMPCParties = 3;
                numSboxes = 43;
                numRounds = 4;
                digestSizeBytes = 32;
                numOpenedRounds = 0;
                break;
            case 11:
                /*Picnic_L3_full*/
                pqSecurityLevel = 96;
                stateSizeBits = 192;
                numMPCRounds = 329;
                numMPCParties = 3;
                numSboxes = 64;
                numRounds = 4;
                digestSizeBytes = 48;
                numOpenedRounds = 0;
                break;
            case 12:
                /*Picnic_L5_full*/
                pqSecurityLevel = 128;
                stateSizeBits = 255;
                numMPCRounds = 438;
                numMPCParties = 3;
                numSboxes = 85;
                numRounds = 4;
                digestSizeBytes = 64;
                numOpenedRounds = 0;
                break;
        default:
            throw new IllegalArgumentException("unknown parameter set " + parameters);
        }

        switch (parameters)
        {
            case 1: /*Picnic_L1_FS*/
                CRYPTO_SECRETKEYBYTES = 49;
                CRYPTO_PUBLICKEYBYTES = 33;
                CRYPTO_BYTES = 34036;
                break;
            case 2: /* Picnic_L1_UR*/
                CRYPTO_SECRETKEYBYTES = 49;
                CRYPTO_PUBLICKEYBYTES = 33;
                CRYPTO_BYTES = 53965;
                break;
            case 3: /*Picnic_L3_FS*/
                CRYPTO_SECRETKEYBYTES = 73;
                CRYPTO_PUBLICKEYBYTES = 49;
                CRYPTO_BYTES = 76784;
                break;
            case 4: /*Picnic_L3_UR*/
                CRYPTO_SECRETKEYBYTES = 73;
                CRYPTO_PUBLICKEYBYTES = 49;
                CRYPTO_BYTES = 121857;
                break;
            case 5: /*Picnic_L5_FS*/
                CRYPTO_SECRETKEYBYTES = 97;
                CRYPTO_PUBLICKEYBYTES = 65;
                CRYPTO_BYTES = 132876;
                break;
            case 6: /*Picnic_L5_UR*/
                CRYPTO_SECRETKEYBYTES = 97;
                CRYPTO_PUBLICKEYBYTES = 65;
                CRYPTO_BYTES = 209526;
                break;
            case 7: /*Picnic3_L1*/
                CRYPTO_SECRETKEYBYTES = 52;
                CRYPTO_PUBLICKEYBYTES = 35;
                CRYPTO_BYTES = 14612;
                break;
            case 8: /*Picnic3_L3*/
                CRYPTO_SECRETKEYBYTES = 73;
                CRYPTO_PUBLICKEYBYTES = 49;
                CRYPTO_BYTES = 35028;
                break;
            case 9: /*Picnic3_L5*/
                CRYPTO_SECRETKEYBYTES = 97;
                CRYPTO_PUBLICKEYBYTES = 65;
                CRYPTO_BYTES = 61028;
                break;
            case 10: /*Picnic_L1_full*/
                CRYPTO_SECRETKEYBYTES = 52;
                CRYPTO_PUBLICKEYBYTES = 35;
                CRYPTO_BYTES = 32061;
                break;
            case 11: /*Picnic_L3_full*/
                CRYPTO_SECRETKEYBYTES = 73;
                CRYPTO_PUBLICKEYBYTES = 49;
                CRYPTO_BYTES = 71179;
                break;
            case 12: /*Picnic_L5_full*/
                CRYPTO_SECRETKEYBYTES = 97;
                CRYPTO_PUBLICKEYBYTES = 65;
                CRYPTO_BYTES = 126286;
                break;
            default:
                CRYPTO_SECRETKEYBYTES = -1;
                CRYPTO_PUBLICKEYBYTES = -1;
                CRYPTO_BYTES = -1;
        }

        // calculated depending on above parameters
        andSizeBytes = Utils.numBytes(numSboxes * 3 * numRounds);
        stateSizeBytes = Utils.numBytes(stateSizeBits);
        seedSizeBytes = Utils.numBytes(2 * pqSecurityLevel);
        stateSizeWords = (stateSizeBits + WORD_SIZE_BITS - 1)/ WORD_SIZE_BITS;



        switch (parameters)
        {
            case 1:
            case 3:
            case 5:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
                transform = TRANSFORM_FS;
                break;
            case 2:
            case 4:
            case 6:
                transform = TRANSFORM_UR;
                break;
            default:
                transform = TRANSFORM_INVALID;
                break;
        }

        if (transform == 1)
        {
            UnruhGWithoutInputBytes = seedSizeBytes + andSizeBytes;
            UnruhGWithInputBytes = UnruhGWithoutInputBytes + stateSizeBytes;
        }
        else
        {
            UnruhGWithoutInputBytes = 0;
            UnruhGWithInputBytes = 0;
        }

        if (stateSizeBits == 128 || stateSizeBits == 129)
        {
            digest = new SHAKEDigest(128);
        }
        else
        {
            digest = new SHAKEDigest(256);
        }
    }

    public boolean crypto_sign_open(byte[] m, byte[] sm, byte[] pk)
    {
        int sigLen = Pack.littleEndianToInt(sm, 0);
        byte[] m_from_sm = Arrays.copyOfRange(sm, 4,  4 + m.length);
        int ret = picnic_verify(pk, m_from_sm, sm, sigLen);
        if (ret == -1)
            return false;
        System.arraycopy(sm, 4, m, 0, m.length);
        return true;
    }

    private int picnic_verify(byte[] pk, byte[] message, byte[] signature, int sigLen)
    {
        int[] ciphertext = new int[stateSizeWords];
        int[] plaintext = new int[stateSizeWords];
        picnic_read_public_key(ciphertext, plaintext, pk);

        if(is_picnic3(parameters))
        {
            Signature2 sig = new Signature2(this);
            int ret = deserializeSignature2(sig, signature, sigLen,  message.length + 4);
            if (ret != 0)
            {
                LOG.fine("Error couldn't deserialize signature (2)!");
                return -1;
            }

            return verify_picnic3(sig, ciphertext, plaintext, message);
        }
        else
        {
            Signature sig = new Signature(this);
            int ret = deserializeSignature(sig, signature, sigLen, message.length + 4);
            if (ret != 0)
            {
                LOG.fine("Error couldn't deserialize signature!");
                return -1;
            }

            return verify(sig, ciphertext, plaintext, message);
        }
    }

    private int verify(Signature sig, int[] pubKey, int[] plaintext, byte[] message)
    {
        byte[][][] as = new byte[numMPCRounds][numMPCParties][digestSizeBytes];
        byte[][][] gs = new byte[numMPCRounds][3][UnruhGWithInputBytes];
        int[][][] viewOutputs = new int[numMPCRounds][3][stateSizeBytes];

        Signature.Proof[] proofs = sig.proofs;

        byte[] received_challengebits = sig.challengeBits;
        int status = 0;
        byte[] computed_challengebits = null;

        byte[] tmp = new byte[Math.max(6 * stateSizeBytes, stateSizeBytes + andSizeBytes)];

        Tape tape = new Tape(this);

        View[] view1s = new View[numMPCRounds];
        View[] view2s = new View[numMPCRounds];

        /* Allocate a slab of memory for the 3rd view's output in each round */
        for (int i = 0; i < numMPCRounds; i++)
        {
            view1s[i] = new View(this);
            view2s[i] = new View(this);

            if (!verifyProof(proofs[i], view1s[i], view2s[i],
                getChallenge(received_challengebits, i), sig.salt, i,
                tmp, plaintext, tape))
            {
                LOG.fine(("Invalid signature. Did not verify"));
                return -1;
            }

            // create ordered array of commitments with order computed based on the challenge
            // check commitments of the two opened views
            int challenge = getChallenge(received_challengebits, i);
            Commit(proofs[i].seed1, 0, view1s[i], as[i][challenge]);
            Commit(proofs[i].seed2, 0, view2s[i], as[i][(challenge + 1) % 3]);
            System.arraycopy(proofs[i].view3Commitment, 0, as[i][(challenge + 2) % 3], 0, digestSizeBytes);
            if (transform == TRANSFORM_UR)
            {
                G(challenge, proofs[i].seed1, 0, view1s[i], gs[i][challenge]);
                G((challenge + 1) % 3, proofs[i].seed2, 0, view2s[i], gs[i][(challenge + 1) % 3]);
                int view3UnruhLength = (challenge == 0) ? UnruhGWithInputBytes : UnruhGWithoutInputBytes;
                System.arraycopy(proofs[i].view3UnruhG, 0, gs[i][(challenge + 2) % 3], 0, view3UnruhLength);
            }

            viewOutputs[i][challenge] = view1s[i].outputShare;
            viewOutputs[i][(challenge + 1) % 3] = view2s[i].outputShare;
            int[] view3Output = new int[stateSizeWords];     /* pointer into the slab to the current 3rd view */
            xor_three(view3Output, view1s[i].outputShare,  view2s[i].outputShare, pubKey);
            viewOutputs[i][(challenge + 2) % 3] = view3Output;
        }

        computed_challengebits = new byte[Utils.numBytes(2 * numMPCRounds)];

        H3(pubKey, plaintext, viewOutputs,
                as, computed_challengebits, sig.salt,
                message, gs);

        if (!subarrayEquals(received_challengebits, computed_challengebits, Utils.numBytes(2 * numMPCRounds)))
        {
            LOG.fine(("Invalid signature. Did not verify"));
            status = -1;
        }

        return status;
    }

    boolean verifyProof(Signature.Proof proof, View view1, View view2, int challenge, byte[] salt,
        int roundNumber, byte[] tmp, int[] plaintext, Tape tape)
    {
        System.arraycopy(proof.communicatedBits, 0, view2.communicatedBits, 0, andSizeBytes);
        tape.pos = 0;

//        System.out.println("tmp: " + Hex.toHexString(tmp));

        boolean status = false;
        switch (challenge)
        {
            case 0:
                // in this case, both views' inputs are derivable from the input share
                status = createRandomTape(proof.seed1, 0, salt, roundNumber,
                        0, tmp, stateSizeBytes + andSizeBytes);

                Pack.littleEndianToInt(tmp, 0, view1.inputShare);//todo check
                System.arraycopy(tmp, stateSizeBytes, tape.tapes[0], 0, andSizeBytes);

                status = status && createRandomTape(proof.seed2,0, salt, roundNumber,
                        1, tmp, stateSizeBytes + andSizeBytes);

                if (!status)
                {
                    break;
                }

                Pack.littleEndianToInt(tmp, 0, view2.inputShare);//todo check
                System.arraycopy(tmp, stateSizeBytes, tape.tapes[1], 0, andSizeBytes);

                break;

            case 1:
                // in this case view2's input share was already given to us explicitly as
                // it is not computable from the seed. We just need to compute view1's input from
                // its seed
                status = createRandomTape(proof.seed1, 0, salt, roundNumber,
                        1, tmp, stateSizeBytes + andSizeBytes);

                Pack.littleEndianToInt(tmp, 0, view1.inputShare);//todo check
                System.arraycopy(tmp, stateSizeBytes, tape.tapes[0], 0, andSizeBytes);
                status = status && createRandomTape(proof.seed2, 0, salt, roundNumber,
                        2, tape.tapes[1], andSizeBytes);

                if (!status)
                {
                    break;
                }

                System.arraycopy(proof.inputShare, 0, view2.inputShare, 0, stateSizeWords);
                break;

            case 2:
                // in this case view1's input share was already given to us explicitly as
                // it is not computable from the seed. We just need to compute view2's input from
                // its seed
                status = createRandomTape(proof.seed1, 0, salt, roundNumber, 2, tape.tapes[0], andSizeBytes);
                System.arraycopy(proof.inputShare, 0, view1.inputShare, 0, stateSizeWords);
                status = status && createRandomTape(proof.seed2, 0, salt, roundNumber, 0, tmp, stateSizeBytes + andSizeBytes);

                if (!status)
                {
                    break;
                }

                Pack.littleEndianToInt(tmp, 0, view2.inputShare);//todo check
                System.arraycopy(tmp, stateSizeBytes, tape.tapes[1], 0, andSizeBytes);
                break;

            default:
                LOG.fine("Invalid Challenge!");
                break;
        }

        if (!status)
        {
            LOG.fine("Failed to generate random tapes, signature verification will fail (but signature may actually be valid)");
            return false;
        }

        Utils.zeroTrailingBits(view1.inputShare, stateSizeBits);
        Utils.zeroTrailingBits(view2.inputShare, stateSizeBits);

        int[] tmp_ints = Pack.littleEndianToInt(tmp, 0, tmp.length/4);
        mpc_LowMC_verify(view1, view2, tape, tmp_ints, plaintext, challenge);
        return true;
    }

    void mpc_LowMC_verify(View view1, View view2, Tape tapes, int[] tmp, int[] plaintext, int challenge)
    {
        Arrays.fill(tmp,0, tmp.length, 0);

        mpc_xor_constant_verify(tmp, plaintext, 0, stateSizeWords, challenge);

        KMatricesWithPointer current = lowmcConstants.KMatrix(this, 0);
        matrix_mul_offset(tmp, 0,
                view1.inputShare, 0,
                current.getData(), current.getMatrixPointer());
        matrix_mul_offset(tmp, stateSizeWords,
                view2.inputShare, 0,
                current.getData(), current.getMatrixPointer());

        mpc_xor(tmp, tmp, 2);

        for (int r = 1; r <= numRounds; ++r)
        {
            current = lowmcConstants.KMatrix(this, r);
            matrix_mul_offset(tmp, 0,
                    view1.inputShare, 0,
                    current.getData(), current.getMatrixPointer());
            matrix_mul_offset(tmp, stateSizeWords,
                    view2.inputShare, 0,
                    current.getData(), current.getMatrixPointer());

            mpc_substitution_verify(tmp, tapes, view1, view2);

            current = lowmcConstants.LMatrix(this, r - 1);
            mpc_matrix_mul(tmp, 2*stateSizeWords,
                    tmp, 2*stateSizeWords,
                    current.getData(), current.getMatrixPointer(), 2);

            current = lowmcConstants.RConstant(this, r - 1);
            mpc_xor_constant_verify(tmp, current.getData(), current.getMatrixPointer(), stateSizeWords, challenge);
            mpc_xor(tmp, tmp, 2);
        }

        System.arraycopy(tmp, 2*stateSizeWords, view1.outputShare, 0, stateSizeWords);
        System.arraycopy(tmp, 3*stateSizeWords, view2.outputShare, 0, stateSizeWords);
    }

    void mpc_substitution_verify(int[] state, Tape rand, View view1, View view2)
    {

        int[] a = new int[2];
        int[] b = new int[2];
        int[] c = new int[2];

        int[] ab = new int[2];
        int[] bc = new int[2];
        int[] ca = new int[2];

        int stateOffset;
        for (int i = 0; i < numSboxes * 3; i += 3)
        {

            for (int j = 0; j < 2; j++)
            {
                stateOffset = ((2+j) * stateSizeWords) * 32;
                a[j] = Utils.getBitFromWordArray(state, stateOffset + i + 2);
                b[j] = Utils.getBitFromWordArray(state, stateOffset + i + 1);
                c[j] = Utils.getBitFromWordArray(state, stateOffset + i);
            }

            mpc_AND_verify(a, b, ab, rand, view1, view2);
            mpc_AND_verify(b, c, bc, rand, view1, view2);
            mpc_AND_verify(c, a, ca, rand, view1, view2);

            for (int j = 0; j < 2; j++)
            {
                stateOffset = ((2+j) * stateSizeWords) * 32;
                Utils.setBitInWordArray(state, stateOffset + i + 2, a[j] ^ (bc[j]));
                Utils.setBitInWordArray(state, stateOffset + i + 1, a[j] ^ b[j] ^ (ca[j]));
                Utils.setBitInWordArray(state, stateOffset + i, a[j] ^ b[j] ^ c[j] ^ (ab[j]));
            }
        }
    }

    void mpc_AND_verify(int[] in1, int[] in2, int[] out, Tape rand, View view1, View view2)
    {
        int r0 = Utils.getBit(rand.tapes[0], rand.pos);
        int r1 = Utils.getBit(rand.tapes[1], rand.pos);

        int a0 = in1[0], a1 = in1[1];
        int b0 = in2[0], b1 = in2[1];

        out[0] = (a0 & b1) ^ (a1 & b0) ^ (a0 & b0) ^ r0 ^ r1;
        Utils.setBit(view1.communicatedBits, rand.pos, (byte)out[0]);
        out[1] = Utils.getBit(view2.communicatedBits, rand.pos);

        rand.pos++;
    }

    private void mpc_xor_constant_verify(int[] state, int[] in, int inOffset ,int length, int challenge)
    {
        /* During verify, where the first share is stored in state depends on the challenge */
        int offset = 0;
        if (challenge == 0)
        {
            offset = 2 * stateSizeWords;
        }
        else if (challenge == 2)
        {
            offset = 3 * stateSizeWords;
        }
        else
        {
            return;
        }
        for (int i = 0; i < length; i++)
        {
            state[i + offset] ^= in[i + inOffset];
        }

    }

    private int deserializeSignature(Signature sig, byte[] sigBytes, int sigBytesLen, int sigBytesOffset)
    {
        Signature.Proof[] proofs = sig.proofs;
        byte[] challengeBits = sig.challengeBits;
        int challengesLength = Utils.numBytes(2 * numMPCRounds);

        /* Validate input buffer is large enough */
        if (sigBytesLen < challengesLength)
        {     /* ensure the input has at least the challenge */
            return -1;
        }

        // NOTE: This also validates that there are no challenges > 2
        int numNonZeroChallenges = countNonZeroChallenges(sigBytes, sigBytesOffset);
        if (numNonZeroChallenges < 0)
            return -1;

        int inputShareSize = numNonZeroChallenges * stateSizeBytes;
        int bytesRequired = challengesLength + saltSizeBytes +
            numMPCRounds * (2 * seedSizeBytes + andSizeBytes + digestSizeBytes) + inputShareSize;

        if (transform == TRANSFORM_UR)
        {
            bytesRequired += UnruhGWithInputBytes * (numMPCRounds - numNonZeroChallenges);
            bytesRequired += UnruhGWithoutInputBytes * numNonZeroChallenges;
        }

        if (sigBytesLen != bytesRequired)
        {
            LOG.fine("sigBytesLen = " + sigBytesLen + ", expected bytesRequired = " + bytesRequired);
            return -1;
        }

        System.arraycopy(sigBytes, sigBytesOffset, challengeBits, 0, challengesLength);
        sigBytesOffset += challengesLength;

        System.arraycopy(sigBytes, sigBytesOffset, sig.salt, 0, saltSizeBytes);
        sigBytesOffset += saltSizeBytes;

        for (int i = 0; i < numMPCRounds; i++)
        {
            int challenge = getChallenge(challengeBits, i);

            System.arraycopy(sigBytes, sigBytesOffset, proofs[i].view3Commitment, 0, digestSizeBytes);

            sigBytesOffset += digestSizeBytes;

            if (transform == TRANSFORM_UR)
            {
                int view3UnruhLength = (challenge == 0) ? UnruhGWithInputBytes : UnruhGWithoutInputBytes;
                System.arraycopy(sigBytes, sigBytesOffset, proofs[i].view3UnruhG, 0, view3UnruhLength);
                sigBytesOffset += view3UnruhLength;
            }

            System.arraycopy(sigBytes, sigBytesOffset, proofs[i].communicatedBits, 0, andSizeBytes);
            sigBytesOffset += andSizeBytes;

            System.arraycopy(sigBytes, sigBytesOffset, proofs[i].seed1, 0, seedSizeBytes);
            sigBytesOffset += seedSizeBytes;

            System.arraycopy(sigBytes, sigBytesOffset, proofs[i].seed2, 0, seedSizeBytes);
            sigBytesOffset += seedSizeBytes;

            if (challenge == 1 || challenge == 2)
            {
                Pack.littleEndianToInt(sigBytes, sigBytesOffset, proofs[i].inputShare, 0, stateSizeBytes/4);
                if( stateSizeBits == 129)
                {
                    proofs[i].inputShare[stateSizeWords - 1] = sigBytes[sigBytesOffset + stateSizeBytes - 1] & 0xff;
                }

                sigBytesOffset += stateSizeBytes;

                if (!arePaddingBitsZero(proofs[i].inputShare, stateSizeBits))
                {
                    return -1;
                }
            }

        }

        return 0;
    }

    private int countNonZeroChallenges(byte[] challengeBits, int challengeBitsOffset)
    {
        /* When the FS transform is used, the input share is included in the proof
         * only when the challenge is 1 or 2.  When deserializing, to compute the
         * number of bytes expected, we must check how many challenge values are 1
         * or 2. We also check that no challenges have the invalid value 3. */
        int count = 0;
        int challenges3 = 0;

        int i = 0;
        while (i + 16 <= numMPCRounds)
        {
            int challenges = Pack.littleEndianToInt(challengeBits, challengeBitsOffset + (i >>> 2));
            challenges3 |= challenges & (challenges >>> 1);
            count += Integers.bitCount((challenges ^ (challenges >>> 1)) & 0x55555555);
            i += 16;
        }

        int remainingBits = (numMPCRounds - i) * 2;
        if (remainingBits > 0)
        {
            int remainingBytes = (remainingBits + 7) / 8;
            int challenges = Pack.littleEndianToInt_Low(challengeBits, challengeBitsOffset + (i >>> 2), remainingBytes);
            challenges &= Utils.getTrailingBitsMask(remainingBits);
            challenges3 |= challenges & (challenges >>> 1);
            count += Integers.bitCount((challenges ^ (challenges >>> 1)) & 0x55555555);
        }

        return (challenges3 & 0x55555555) == 0 ? count : -1;
    }

    private void picnic_read_public_key(int[] ciphertext, int[] plaintext, byte[] pk)
    {
        int ciphertextPos = 1, plaintextPos = 1 + stateSizeBytes;
        int fullWords = stateSizeBytes / 4;
        Pack.littleEndianToInt(pk, ciphertextPos, ciphertext, 0, fullWords);
        Pack.littleEndianToInt(pk, plaintextPos, plaintext, 0, fullWords);

        if (fullWords < stateSizeWords)
        {
            int fullWordBytes = fullWords * 4, partialWordBytes = stateSizeBytes - fullWordBytes;
            ciphertext[fullWords] = Pack.littleEndianToInt_Low(pk, ciphertextPos + fullWordBytes, partialWordBytes);
            plaintext[fullWords] = Pack.littleEndianToInt_Low(pk, plaintextPos + fullWordBytes, partialWordBytes);
        }
    }

    private int verify_picnic3(Signature2 sig, int[] pubKey, int[] plaintext, byte[] message)
    {
        byte[][][] C = new byte[numMPCRounds][numMPCParties][digestSizeBytes];
        byte[][] Ch = new byte[numMPCRounds][digestSizeBytes];
        byte[][] Cv = new byte[numMPCRounds][digestSizeBytes];
        Msg[] msgs = new Msg[numMPCRounds];

        Tree treeCv = new Tree(this, numMPCRounds, digestSizeBytes);
        byte[] challengeHash = new byte[MAX_DIGEST_SIZE];
        Tree[] seeds = new Tree[numMPCRounds];
        Tape[] tapes = new Tape[numMPCRounds];
        Tree iSeedsTree = new Tree(this, numMPCRounds, seedSizeBytes);

        int ret = iSeedsTree.reconstructSeeds(sig.challengeC, numOpenedRounds,
                sig.iSeedInfo, sig.iSeedInfoLen, sig.salt, 0);
        
        if (ret != 0)
        {
            return -1;
        }

        /* Populate seeds with values from the signature */
        for (int t = 0; t < numMPCRounds; t++)
        {
            if (!contains(sig.challengeC, numOpenedRounds, t))
            {
                /* Expand iSeed[t] to seeds for each parties, using a seed tree */
                seeds[t] = new Tree(this, numMPCParties, seedSizeBytes);
                seeds[t].generateSeeds(iSeedsTree.getLeaf(t), sig.salt, t);
            }
            else
            {
                /* We don't have the initial seed for the round, but instead a seed
                 * for each unopened party */
                seeds[t] = new Tree(this, numMPCParties, seedSizeBytes);
                int P_index = indexOf(sig.challengeC, numOpenedRounds, t);
                int[] hideList = new int[1];
                hideList[0] = sig.challengeP[P_index];
                ret = seeds[t].reconstructSeeds(hideList, 1,
                        sig.proofs[t].seedInfo, sig.proofs[t].seedInfoLen,
                        sig.salt, t);
                if (ret != 0)
                {
                    LOG.fine("Failed to reconstruct seeds for round " + t);
                    return -1;
                }
            }
        }

        /* Commit */
        int last = numMPCParties - 1;
        byte[] auxBits = new byte[MAX_AUX_BYTES];
        for (int t = 0; t < numMPCRounds; t++)
        {
            tapes[t] = new Tape(this);
            /* Compute random tapes for all parties.  One party for each repitition
             * challengeC will have a bogus seed; but we won't use that party's
             * random tape. */
            createRandomTapes(tapes[t], seeds[t].getLeaves(), seeds[t].getLeavesOffset(), sig.salt, t);



            if (!contains(sig.challengeC, numOpenedRounds, t))
            {
                /* We're given iSeed, have expanded the seeds, compute aux from scratch so we can comnpte Com[t] */
                tapes[t].computeAuxTape(null);
                for (int j = 0; j < last; j++)
                {
                    commit(C[t][j], seeds[t].getLeaf(j), null, sig.salt, t, j);
                }
                getAuxBits(auxBits, tapes[t]);
                commit(C[t][last], seeds[t].getLeaf(last), auxBits, sig.salt, t, last);
            }
            else
            {
                /* We're given all seeds and aux bits, except for the unopened
                 * party, we get their commitment */
                int unopened = sig.challengeP[indexOf(sig.challengeC, numOpenedRounds, t)];


                for (int j = 0; j < last; j++)
                {
                    if (j != unopened)
                    {
                        commit(C[t][j], seeds[t].getLeaf(j), null, sig.salt, t, j);
                    }
                }
                if (last != unopened)
                {
                    commit(C[t][last], seeds[t].getLeaf(last), sig.proofs[t].aux, sig.salt, t, last);
                }

                System.arraycopy(sig.proofs[t].C, 0, C[t][unopened], 0, digestSizeBytes);
            }

        }

        /* Commit to the commitments */
        for (int t = 0; t < numMPCRounds; t++)
        {
            commit_h(Ch[t], C[t]);
        }

        /* Commit to the views */
        int[] tmp_shares = new int[stateSizeBits];
        for (int t = 0; t < numMPCRounds; t++)
        {
            msgs[t] = new Msg(this);
            if (contains(sig.challengeC, numOpenedRounds, t))
            {
                /* 2. When t is in C, we have everything we need to re-compute the view, as an honest signer would.
                 * We simulate the MPC with one fewer party; the unopned party's values are all set to zero. */
                int unopened = sig.challengeP[indexOf(sig.challengeC, numOpenedRounds, t)];

//                int tapeLengthBytes = 2 * andSizeBytes;
                if(unopened != last)
                {  // sig.proofs[t].aux is only set when P_t != N
                    tapes[t].setAuxBits(sig.proofs[t].aux);
                }
                System.arraycopy(sig.proofs[t].msgs, 0, msgs[t].msgs[unopened], 0, andSizeBytes);

                Arrays.fill(tapes[t].tapes[unopened], (byte) 0);
                msgs[t].unopened = unopened;

                byte[] input_bytes = new byte[stateSizeWords * 4];
                System.arraycopy(sig.proofs[t].input, 0, input_bytes, 0, sig.proofs[t].input.length);

                int[] temp = new int[stateSizeWords];
                Pack.littleEndianToInt(input_bytes, 0, temp, 0, stateSizeWords);

                int rv = simulateOnline(temp, tapes[t], tmp_shares, msgs[t], plaintext, pubKey);
                if (rv != 0)
                {
                    LOG.fine("MPC simulation failed for round " + t + ", signature invalid");
                    return -1;
                }
                commit_v(Cv[t], sig.proofs[t].input, msgs[t]);
            }
            else
            {
                Cv[t] = null;
            }
        }

        int missingLeavesSize = numMPCRounds - numOpenedRounds;
        int[] missingLeaves = getMissingLeavesList(sig.challengeC);
        ret = treeCv.addMerkleNodes(missingLeaves, missingLeavesSize, sig.cvInfo, sig.cvInfoLen);
        if (ret != 0)
        {
            return -1;
        }

        ret = treeCv.verifyMerkleTree(Cv, sig.salt);
        if (ret != 0)
        {
            return -1;
        }

        /* Compute the challenge hash */
        HCP(challengeHash, null, null, Ch, treeCv.nodes[0], sig.salt, pubKey, plaintext, message);

        /* Compare to challenge from signature */
        if (!subarrayEquals(sig.challengeHash, challengeHash, digestSizeBytes))
        {
            LOG.fine("Challenge does not match, signature invalid");
            return -1;
        }
        return ret;
    }

    private int deserializeSignature2(Signature2 sig, byte[] sigBytes, int sigLen,  int sigBytesOffset)
    {
        /* Read the challenge and salt */
        int bytesRequired = digestSizeBytes + saltSizeBytes;

        if (sigBytes.length < bytesRequired)
        {
            return -1;
        }

        System.arraycopy(sigBytes, sigBytesOffset, sig.challengeHash, 0, digestSizeBytes);
        sigBytesOffset += digestSizeBytes;

        System.arraycopy(sigBytes, sigBytesOffset, sig.salt, 0, saltSizeBytes);
        sigBytesOffset += saltSizeBytes;

        expandChallengeHash(sig.challengeHash, sig.challengeC, sig.challengeP);

        /* Add size of iSeeds tree data */
        Tree tree = new Tree(this, numMPCRounds, seedSizeBytes);
        sig.iSeedInfoLen = tree.revealSeedsSize(sig.challengeC, numOpenedRounds);
        bytesRequired += sig.iSeedInfoLen;
//        System.out.printf("iSeedInfoLen: %04x\n", sig.iSeedInfoLen);

        /* Add the size of the Cv Merkle tree data */
        int missingLeavesSize = numMPCRounds - numOpenedRounds;
        int[] missingLeaves = getMissingLeavesList(sig.challengeC);
        tree = new Tree(this, numMPCRounds, digestSizeBytes);
        sig.cvInfoLen = tree.openMerkleTreeSize(missingLeaves, missingLeavesSize);
        bytesRequired += sig.cvInfoLen;

        /* Compute the number of bytes required for the proofs */
        int[] hideList = new int[1];
        tree = new Tree(this, numMPCParties, seedSizeBytes);
        int seedInfoLen = tree.revealSeedsSize(hideList, 1);
        for (int t = 0; t < numMPCRounds; t++)
        {
            if (contains(sig.challengeC, numOpenedRounds, t))
            {
                int P_t = sig.challengeP[indexOf(sig.challengeC, numOpenedRounds, t)];
                if (P_t != (numMPCParties - 1))
                {
                    bytesRequired += andSizeBytes;
                }
                bytesRequired += seedInfoLen;
                bytesRequired += stateSizeBytes;
                bytesRequired += andSizeBytes;
                bytesRequired += digestSizeBytes;
            }
        }

        /* Fail if the signature does not have the exact number of bytes we expect */
        if (sigLen != bytesRequired)
        {
            LOG.fine("sigLen = " + sigLen + ", expected bytesRequired = " + bytesRequired);
            return -1;
        }

        sig.iSeedInfo = new byte[sig.iSeedInfoLen];
        System.arraycopy(sigBytes, sigBytesOffset, sig.iSeedInfo, 0, sig.iSeedInfoLen);
        sigBytesOffset += sig.iSeedInfoLen;
//        System.out.println("iSeedInfo: " + Hex.toHexString(sig.iSeedInfo));

        sig.cvInfo = new byte[sig.cvInfoLen];
        System.arraycopy(sigBytes, sigBytesOffset, sig.cvInfo, 0, sig.cvInfoLen);
        sigBytesOffset += sig.cvInfoLen;

        /* Read the proofs */
        for (int t = 0; t < numMPCRounds; t++)
        {
            if (contains(sig.challengeC, numOpenedRounds, t))
            {
                sig.proofs[t] = new Signature2.Proof2(this);
                sig.proofs[t].seedInfoLen = seedInfoLen;
                sig.proofs[t].seedInfo = new byte[sig.proofs[t].seedInfoLen];
                System.arraycopy(sigBytes, sigBytesOffset, sig.proofs[t].seedInfo, 0, sig.proofs[t].seedInfoLen);
                sigBytesOffset += sig.proofs[t].seedInfoLen;

                int P_t = sig.challengeP[indexOf(sig.challengeC, numOpenedRounds, t)];
                if (P_t != (numMPCParties - 1) )
                {
                    System.arraycopy(sigBytes, sigBytesOffset, sig.proofs[t].aux, 0, andSizeBytes);
                    sigBytesOffset += andSizeBytes;
                    if (!arePaddingBitsZero(sig.proofs[t].aux, 3 * numRounds * numSboxes))
                    {
                        LOG.fine("failed while deserializing aux bits");
                        return -1;
                    }
                }
                System.arraycopy(sigBytes, sigBytesOffset, sig.proofs[t].input, 0, stateSizeBytes);
                sigBytesOffset +=stateSizeBytes;

                int msgsByteLength = andSizeBytes;
                System.arraycopy(sigBytes, sigBytesOffset, sig.proofs[t].msgs, 0, msgsByteLength);
                sigBytesOffset +=msgsByteLength;
                int msgsBitLength =  3 * numRounds * numSboxes;
                if (!arePaddingBitsZero(sig.proofs[t].msgs, msgsBitLength))
                {
                    LOG.fine("failed while deserializing msgs bits");
                    return -1;
                }

                System.arraycopy(sigBytes, sigBytesOffset, sig.proofs[t].C, 0, digestSizeBytes);
                sigBytesOffset +=digestSizeBytes;
            }
        }

        return 0;
    }

    private boolean arePaddingBitsZero(byte[] data, int bitLength)
    {
        int byteLength = Utils.numBytes(bitLength);
        for (int i = bitLength; i < byteLength * 8; i++)
        {
            int bit_i = Utils.getBit(data, i);
            if (bit_i != 0)
            {
                return false;
            }
        }
        return true;
    }

    private boolean arePaddingBitsZero(int[] data, int bitLength)
    {
        int partialWord = bitLength & 31;
        if (partialWord == 0)
            return true;

        int mask = Utils.getTrailingBitsMask(bitLength);
        return (data[bitLength >>> 5] & ~mask) == 0;
    }

    public void crypto_sign(byte[] sm, byte[] m, byte[] sk)
    {
        boolean ret = picnic_sign(sk, m, sm);
        if(!ret)
        {
            return; // throw error?
        }
        System.arraycopy(m, 0, sm, 4, m.length);
    }

    private boolean picnic_sign(byte[] sk, byte[] message, byte[] signature)
    {
        int[] data = new int[stateSizeWords];
        int[] ciphertext = new int[stateSizeWords];
        int[] plaintext = new int[stateSizeWords];

        int dataPos = 1, ciphertextPos = 1 + stateSizeBytes, plaintextPos = 1 + 2 * stateSizeBytes;
        int fullWords = stateSizeBytes / 4;
        Pack.littleEndianToInt(sk, dataPos, data, 0, fullWords);
        Pack.littleEndianToInt(sk, ciphertextPos, ciphertext, 0, fullWords);
        Pack.littleEndianToInt(sk, plaintextPos, plaintext, 0, fullWords);

        if (fullWords < stateSizeWords)
        {
            int fullWordBytes = fullWords * 4, partialWordBytes = stateSizeBytes - fullWordBytes;
            data[fullWords] = Pack.littleEndianToInt_Low(sk, dataPos + fullWordBytes, partialWordBytes);
            ciphertext[fullWords] = Pack.littleEndianToInt_Low(sk, ciphertextPos + fullWordBytes, partialWordBytes);
            plaintext[fullWords] = Pack.littleEndianToInt_Low(sk, plaintextPos + fullWordBytes, partialWordBytes);
        }

        if(!is_picnic3(parameters))
        {
            Signature sig = new Signature (this);

            int ret = sign_picnic1(data, ciphertext, plaintext, message, sig);
            if (ret != 0)
            {
                LOG.fine("Failed to create signature");
                return false;
            }

            int len = serializeSignature(sig, signature, message.length + 4);
            if (len < 0)
            {
                LOG.fine("Failed to serialize signature");
                return false;
            }

            signatureLength = len;
            Pack.intToLittleEndian(len, signature, 0);
            return true;
        }
        else
        {
            Signature2 sig = new Signature2(this);
            boolean ret = sign_picnic3(data, ciphertext, plaintext, message, sig);
            if (!ret)
            {
                LOG.fine("Failed to create signature");
                return false;
            }

            int len = serializeSignature2(sig, signature, message.length + 4);
            if (len < 0)
            {
                LOG.fine("Failed to serialize signature");
                return false;
            }

            signatureLength = len;
            Pack.intToLittleEndian(len, signature, 0);
            return true;
        }
    }

    /*** Serialization functions ***/

    int serializeSignature(Signature sig, byte[] sigBytes, int sigOffset)
    {
        Signature.Proof[] proofs = sig.proofs;
        byte[] challengeBits = sig.challengeBits;

        /* Validate input buffer is large enough */
        int bytesRequired = Utils.numBytes(2 * numMPCRounds) + saltSizeBytes +
                numMPCRounds * (2 * seedSizeBytes + stateSizeBytes + andSizeBytes + digestSizeBytes);

        if (transform == TRANSFORM_UR)
        {
            bytesRequired += UnruhGWithoutInputBytes * numMPCRounds;
        }

        if (CRYPTO_BYTES < bytesRequired)
        {
            return -1;
        }

        int sigByteIndex = sigOffset;

        System.arraycopy(challengeBits, 0, sigBytes, sigByteIndex, Utils.numBytes(2 * numMPCRounds) );
        sigByteIndex += Utils.numBytes(2 * numMPCRounds);

        System.arraycopy(sig.salt, 0, sigBytes, sigByteIndex,saltSizeBytes);
        sigByteIndex += saltSizeBytes;

        for (int i = 0; i < numMPCRounds; i++)
        {
            int challenge = getChallenge(challengeBits, i);

            System.arraycopy(proofs[i].view3Commitment, 0, sigBytes, sigByteIndex, digestSizeBytes);
            sigByteIndex += digestSizeBytes;

            if (transform == TRANSFORM_UR)
            {
                int view3UnruhLength = (challenge == 0) ? UnruhGWithInputBytes : UnruhGWithoutInputBytes;
                System.arraycopy(proofs[i].view3UnruhG, 0, sigBytes, sigByteIndex, view3UnruhLength);
                sigByteIndex += view3UnruhLength;
            }

            System.arraycopy(proofs[i].communicatedBits, 0, sigBytes, sigByteIndex, andSizeBytes);
            sigByteIndex += andSizeBytes;

            System.arraycopy(proofs[i].seed1, 0, sigBytes, sigByteIndex, seedSizeBytes);
            sigByteIndex += seedSizeBytes;

            System.arraycopy(proofs[i].seed2, 0, sigBytes, sigByteIndex, seedSizeBytes);
            sigByteIndex += seedSizeBytes;

            if (challenge == 1 || challenge == 2)
            {
                Pack.intToLittleEndian(proofs[i].inputShare, 0, stateSizeWords , sigBytes, sigByteIndex);
                sigByteIndex += stateSizeBytes;
            }

        }

        return sigByteIndex - sigOffset;
    }

    int getChallenge(byte[] challenge, int round)
    {
        return Utils.getCrumbAligned(challenge, round);
    }

    private int serializeSignature2(Signature2 sig, byte[] sigBytes, int sigOffset)
    {
        /* Compute the number of bytes required for the signature */
        int bytesRequired = digestSizeBytes + saltSizeBytes;     /* challenge and salt */

        bytesRequired += sig.iSeedInfoLen;     /* Encode only iSeedInfo, the length will be recomputed by deserialize */
        bytesRequired += sig.cvInfoLen;

        for (int t = 0; t < numMPCRounds; t++)
        {   /* proofs */
            if (contains(sig.challengeC, numOpenedRounds, t))
            {
                int P_t = sig.challengeP[indexOf(sig.challengeC, numOpenedRounds, t)];
                bytesRequired += sig.proofs[t].seedInfoLen;
                if (P_t != (numMPCParties - 1))
                {
                    bytesRequired += andSizeBytes;
                }
                bytesRequired += stateSizeBytes;
                bytesRequired += andSizeBytes;
                bytesRequired += digestSizeBytes;
            }
        }

        if (sigBytes.length < bytesRequired)
        {
            return -1;
        }

        int sigByteIndex = sigOffset;
        System.arraycopy(sig.challengeHash, 0, sigBytes, sigByteIndex, digestSizeBytes);
        sigByteIndex += digestSizeBytes;

        System.arraycopy(sig.salt, 0, sigBytes, sigByteIndex, saltSizeBytes);
        sigByteIndex += saltSizeBytes;

        System.arraycopy(sig.iSeedInfo, 0, sigBytes, sigByteIndex, sig.iSeedInfoLen);
        sigByteIndex += sig.iSeedInfoLen;

        System.arraycopy(sig.cvInfo, 0, sigBytes, sigByteIndex, sig.cvInfoLen);
        sigByteIndex += sig.cvInfoLen;

        /* Write the proofs */
        for (int t = 0; t < numMPCRounds; t++)
        {
            if (contains(sig.challengeC, numOpenedRounds, t))
            {
                System.arraycopy(sig.proofs[t].seedInfo, 0, sigBytes, sigByteIndex, sig.proofs[t].seedInfoLen);
                sigByteIndex += sig.proofs[t].seedInfoLen;

                int P_t = sig.challengeP[indexOf(sig.challengeC, numOpenedRounds, t)];

                if (P_t != (numMPCParties - 1) )
                {
                    System.arraycopy(sig.proofs[t].aux, 0, sigBytes, sigByteIndex, andSizeBytes);
                    sigByteIndex += andSizeBytes;
                }

                System.arraycopy(sig.proofs[t].input, 0, sigBytes, sigByteIndex, stateSizeBytes);
                sigByteIndex += stateSizeBytes;

                System.arraycopy(sig.proofs[t].msgs, 0, sigBytes, sigByteIndex, andSizeBytes);
                sigByteIndex += andSizeBytes;

                System.arraycopy(sig.proofs[t].C, 0, sigBytes, sigByteIndex, digestSizeBytes);
                sigByteIndex += digestSizeBytes;
            }
        }

        return sigByteIndex - sigOffset;
    }

    private int sign_picnic1(int[] privateKey, int[] pubKey, int[] plaintext, byte[] message, Signature sig)
    {
        boolean status;

        /* Allocate views and commitments for all parallel iterations */
        View[][] views = new View[numMPCRounds][3];
        byte[][][] as = new byte[numMPCRounds][numMPCParties][digestSizeBytes];
        byte[][][] gs = new byte[numMPCRounds][3][UnruhGWithInputBytes];

        /* Compute seeds for all parallel iterations */
        byte[] seeds = computeSeeds(privateKey, pubKey, plaintext, message);
        int seedLen = numMPCParties * seedSizeBytes;

        System.arraycopy(seeds, (seedLen)*(numMPCRounds), sig.salt, 0, saltSizeBytes);

        //Allocate a random tape (re-used per parallel iteration), and a temporary buffer
        Tape tape = new Tape(this);

        byte[] tmp = new byte[Math.max(9 * stateSizeBytes, stateSizeBytes + andSizeBytes)];

        for (int k = 0; k < numMPCRounds; k++)
        {
            views[k][0] = new View(this);
            views[k][1] = new View(this);
            views[k][2] = new View(this);
            // for first two players get all tape INCLUDING INPUT SHARE from seed
            for (int j = 0; j < 2; j++)
            {
                status = createRandomTape(seeds,(seedLen)*k + j*seedSizeBytes,
                        sig.salt, k, j, tmp, stateSizeBytes + andSizeBytes);
                if (!status) 
                {
                    LOG.fine("createRandomTape failed");
                    return -1;
                }

                int[] inputShare = views[k][j].inputShare;
                Pack.littleEndianToInt(tmp, 0, inputShare);
                Utils.zeroTrailingBits(inputShare, stateSizeBits);
                
                System.arraycopy(tmp, stateSizeBytes, tape.tapes[j], 0, andSizeBytes);
            }

            // Now set third party's wires. The random bits are from the seed, the input is
            // the XOR of other two inputs and the private key
            status = createRandomTape(seeds, (seedLen)*k + 2*seedSizeBytes,
                    sig.salt, k, 2, tape.tapes[2], andSizeBytes);
            if (!status)
            {
                LOG.fine("createRandomTape failed");
                return -1;
            }

            xor_three(views[k][2].inputShare, privateKey, views[k][0].inputShare, views[k][1].inputShare);
            tape.pos = 0;

            int[] tmp_int = Pack.littleEndianToInt(tmp, 0, tmp.length/4);

            mpc_LowMC(tape, views[k], plaintext, tmp_int);
            Pack.intToLittleEndian(tmp_int, tmp, 0);

            int[] temp = new int[LOWMC_MAX_WORDS];
            xor_three(temp, views[k][0].outputShare, views[k][1].outputShare, views[k][2].outputShare);

            if(!subarrayEquals(temp, pubKey, stateSizeWords))
            {
                LOG.fine("Simulation failed; output does not match public key (round = " + k + ")");
                return -1;
            }

            //Committing
            Commit(seeds, ((seedLen) * k) + 0 * seedSizeBytes, views[k][0], as[k][0]);
            Commit(seeds, ((seedLen) * k) + 1 * seedSizeBytes, views[k][1], as[k][1]);
            Commit(seeds, ((seedLen) * k) + 2 * seedSizeBytes, views[k][2], as[k][2]);

            if (transform == TRANSFORM_UR)
            {
                G(0, seeds, ((seedLen) * k) + 0 * seedSizeBytes, views[k][0], gs[k][0]);
                G(1, seeds, ((seedLen) * k) + 1 * seedSizeBytes, views[k][1], gs[k][1]);
                G(2, seeds, ((seedLen) * k) + 2 * seedSizeBytes, views[k][2], gs[k][2]);
            }
        }

        //Generating challenges

        H3(pubKey, plaintext, views, as, sig.challengeBits, sig.salt, message, gs);

        //Packing Z
        for (int i = 0; i < numMPCRounds; i++)
        {
            Signature.Proof proof = sig.proofs[i];
            prove(proof, getChallenge(sig.challengeBits, i), seeds, ((seedLen) * i),
                    views[i], as[i], (transform != TRANSFORM_UR) ? null : gs[i]); //todo check if
        }

        return 0;
    }

    /* Caller must allocate the first parameter */
    void prove(Signature.Proof proof, int challenge, byte[] seeds, int seedsOffset,
               View[] views, byte[][] commitments, byte[][] gs)
    {
        if (challenge == 0)
        {
            System.arraycopy(seeds, seedsOffset + 0 * seedSizeBytes, proof.seed1, 0, seedSizeBytes);
            System.arraycopy(seeds, seedsOffset + 1 * seedSizeBytes, proof.seed2, 0, seedSizeBytes);
        }
        else if (challenge == 1) 
        {
            System.arraycopy(seeds, seedsOffset + 1 * seedSizeBytes, proof.seed1, 0, seedSizeBytes);
            System.arraycopy(seeds, seedsOffset + 2 * seedSizeBytes, proof.seed2, 0, seedSizeBytes);
        }
        else if (challenge == 2) 
        {
            System.arraycopy(seeds, seedsOffset + 2 * seedSizeBytes, proof.seed1, 0, seedSizeBytes);
            System.arraycopy(seeds, seedsOffset + 0 * seedSizeBytes, proof.seed2, 0, seedSizeBytes);
        }
        else 
        {
            LOG.fine("Invalid challenge");
            throw new IllegalArgumentException("challenge");
        }

        if (challenge == 1 || challenge == 2)
        {
            System.arraycopy(views[2].inputShare, 0, proof.inputShare, 0, stateSizeWords);
        }

        System.arraycopy(views[(challenge + 1) % 3].communicatedBits, 0, proof.communicatedBits, 0, andSizeBytes);

        System.arraycopy(commitments[(challenge + 2) % 3], 0, proof.view3Commitment, 0, digestSizeBytes);
        if (transform == TRANSFORM_UR)
        {
            int view3UnruhLength = (challenge == 0) ? UnruhGWithInputBytes : UnruhGWithoutInputBytes;
            System.arraycopy(gs[(challenge + 2) % 3], 0, proof.view3UnruhG, 0, view3UnruhLength);
        }
    }

    private void H3(int[] circuitOutput, int[] plaintext, View[][] views, byte[][][] as, byte[] challengeBits,
        byte[] salt, byte[] message, byte[][][] gs)
    {
        digest.update((byte) 1);

        byte[] tmp = new byte[stateSizeWords * 4];
        
        /* Hash the output share from each view */
        for (int i = 0; i < numMPCRounds; i++) 
        {
            for (int j = 0; j < 3; j++) 
            {
                Pack.intToLittleEndian(views[i][j].outputShare, tmp, 0);
                digest.update(tmp, 0, stateSizeBytes);
            }
        }

        implH3(circuitOutput, plaintext, as, challengeBits, salt, message, gs);
    }

    private void H3(int[] circuitOutput, int[] plaintext, int[][][] viewOutputs, byte[][][] as, byte[] challengeBits,
        byte[] salt, byte[] message, byte[][][] gs)
    {
        digest.update((byte) 1);

        byte[] tmp = new byte[stateSizeWords * 4];
        
        /* Hash the output share from each view */
        for (int i = 0; i < numMPCRounds; i++) 
        {
            for (int j = 0; j < 3; j++) 
            {
                Pack.intToLittleEndian(viewOutputs[i][j], tmp, 0);
                digest.update(tmp, 0, stateSizeBytes);
            }
        }

        implH3(circuitOutput, plaintext, as, challengeBits, salt, message, gs);
    }

    private void implH3(int[] circuitOutput, int[] plaintext, byte[][][] as, byte[] challengeBits, byte[] salt,
        byte[] message, byte[][][] gs)
    {
        byte[] hash = new byte[digestSizeBytes];

        /* Depending on the number of rounds, we might not set part of the last
         * byte, make sure it's always zero. */
        challengeBits[Utils.numBytes(numMPCRounds * 2) - 1] = 0;

        /* Hash all the commitments C */
        for (int i = 0; i < numMPCRounds; i++) 
        {
            for (int j = 0; j < 3; j++) 
            {
                digest.update(as[i][j], 0, digestSizeBytes);
            }
        }

        /* Hash all the commitments G */
        if (transform == TRANSFORM_UR)
        {
            for (int i = 0; i < numMPCRounds; i++)
            {
                for (int j = 0; j < 3; j++) 
                {
                    int view3UnruhLength = (j == 2) ? UnruhGWithInputBytes : UnruhGWithoutInputBytes;
                    digest.update(gs[i][j], 0, view3UnruhLength);
                }
            }
        }

        /* Hash the public key */
        digest.update(Pack.intToLittleEndian(circuitOutput), 0, stateSizeBytes);
        digest.update(Pack.intToLittleEndian(plaintext), 0, stateSizeBytes);

        /* Hash the salt & message */
        digest.update(salt, 0, saltSizeBytes);
        digest.update(message, 0, message.length);
        digest.doFinal(hash, 0, digestSizeBytes);

        /* Convert hash to a packed string of values in {0,1,2} */
        int round = 0;
        boolean isNotDone = true;
        while (isNotDone)
        {
            for (int i = 0; i < digestSizeBytes; i++)
            {
                int one_byte = hash[i];
                /* iterate over each pair of bits in the byte */
                for (int j = 0; j < 8; j += 2) 
                {
                    int bitPair = ((one_byte >>> (6 - j)) & 0x03);
                    if (bitPair < 3) 
                    {
                        setChallenge(challengeBits, round, bitPair);
                        round++;
                        if (round == numMPCRounds) 
                        {
                            isNotDone = false;
                            break;
                        }
                    }
                }
                if(!isNotDone)
                {
                    break;
                }
            }
            if(!isNotDone)
            {
                break;
            }
            /* We need more bits; hash set hash = H_1(hash) */
            digest.update((byte) 1);
            digest.update(hash, 0, digestSizeBytes);
            digest.doFinal(hash, 0, digestSizeBytes);
        }
    }

    private void setChallenge(byte[] challenge, int round, int trit)
    {
        /* challenge must have length numBytes(numMPCRounds*2)
         * 0 <= index < numMPCRounds
         * trit must be in {0,1,2} */
        Utils.setBit(challenge, 2 * round, (byte) (trit & 1));
        Utils.setBit(challenge, 2 * round + 1, (byte)((trit >>> 1) & 1));
    }

    /* This is the random "permuatation" function G for Unruh's transform */
    private void G(int viewNumber, byte[] seed, int seedOffset, View view, byte[] output)
    {
        int outputBytes = seedSizeBytes + andSizeBytes;

        /* Hash the seed with H_5, store digest in output */
        digest.update((byte) 5);
        digest.update(seed, seedOffset, seedSizeBytes);
        digest.doFinal(output, 0, digestSizeBytes);

        /* Hash H_5(seed), the view, and the length */
        digest.update(output, 0, digestSizeBytes);
        if (viewNumber == 2)
        {
            digest.update(Pack.intToLittleEndian(view.inputShare), 0, stateSizeBytes);
            outputBytes += stateSizeBytes;
        }
        digest.update(view.communicatedBits, 0, andSizeBytes);

        digest.update(Pack.intToLittleEndian(outputBytes), 0, 2);
        digest.doFinal(output, 0, outputBytes);
    }

    private void mpc_LowMC(Tape tapes, View[] views, int[] plaintext, int[] slab)
    {
        Arrays.fill(slab, 0, slab.length, 0);

        mpc_xor_constant(slab, 3*stateSizeWords, plaintext, 0, stateSizeWords);

        KMatricesWithPointer current = lowmcConstants.KMatrix(this, 0);
        for (int player = 0; player < 3; player++)
        {
            matrix_mul_offset(slab, player  * stateSizeWords, views[player].inputShare, 0,
                    current.getData(), current.getMatrixPointer());
        }

        mpc_xor(slab, slab, 3);

        for (int r = 1; r <= numRounds; r++)
        {
            current = lowmcConstants.KMatrix(this, r);
            for (int player = 0; player < 3; player++)
            {
                matrix_mul_offset(slab, player  * stateSizeWords,
                        views[player].inputShare, 0,
                        current.getData(), current.getMatrixPointer());
            }

            mpc_substitution(slab, tapes, views);

            current = lowmcConstants.LMatrix(this, r - 1);
            mpc_matrix_mul(slab, 3*stateSizeWords,
                           slab, 3*stateSizeWords,
                           current.getData(), current.getMatrixPointer(), 3);

            current = lowmcConstants.RConstant(this, r - 1);
            mpc_xor_constant(slab, 3*stateSizeWords,
                             current.getData(), current.getMatrixPointer(), stateSizeWords);

            mpc_xor(slab, slab, 3);
        }

        for (int i = 0; i < 3; i++)
        {
            System.arraycopy(slab, (3 + i) * stateSizeWords, views[i].outputShare, 0, stateSizeWords);
        }
    }

    private void Commit(byte[] seed, int seedOffset, View view, byte[] hash)
    {
        /* Hash the seed, store result in `hash` */
        digest.update((byte)4);
        digest.update(seed, seedOffset, seedSizeBytes);
        digest.doFinal(hash, 0, digestSizeBytes);

        /* Compute H_0(H_4(seed), view) */
        digest.update((byte) 0);
        digest.update(hash, 0, digestSizeBytes);
        digest.update(Pack.intToLittleEndian(view.inputShare), 0, stateSizeBytes);
        digest.update(view.communicatedBits, 0, andSizeBytes);
        digest.update(Pack.intToLittleEndian(view.outputShare), 0, stateSizeBytes);
        digest.doFinal(hash, 0, digestSizeBytes);
    }

    private void mpc_substitution(int[] state, Tape rand, View[] views)
    {
        int[] a = new int[3];
        int[] b = new int[3];
        int[] c = new int[3];

        int[] ab = new int[3];
        int[] bc = new int[3];
        int[] ca = new int[3];

        int stateOffset;
        for (int i = 0; i < numSboxes * 3; i += 3)
        {

            for (int j = 0; j < 3; j++)
            {
                stateOffset = ((3+j) * stateSizeWords) * 32;
                a[j] = Utils.getBitFromWordArray(state, stateOffset + i + 2);
                b[j] = Utils.getBitFromWordArray(state, stateOffset + i + 1);
                c[j] = Utils.getBitFromWordArray(state, stateOffset + i);
            }

            mpc_AND(a, b, ab, rand, views);
            mpc_AND(b, c, bc, rand, views);
            mpc_AND(c, a, ca, rand, views);

            for (int j = 0; j < 3; j++)
            {
                stateOffset = ((3+j) * stateSizeWords) * 32;
                Utils.setBitInWordArray(state, stateOffset + i + 2, a[j] ^ (bc[j]));
                Utils.setBitInWordArray(state, stateOffset + i + 1, a[j] ^ b[j] ^ (ca[j]));
                Utils.setBitInWordArray(state, stateOffset + i, a[j] ^ b[j] ^ c[j] ^ (ab[j]));
            }
        }
    }

    /*** Functions implementing Sign ***/
    private void mpc_AND(int[] in1, int[] in2, int[] out, Tape rand, View[] views)
    {
        int r0 = Utils.getBit(rand.tapes[0], rand.pos);
        int r1 = Utils.getBit(rand.tapes[1], rand.pos);
        int r2 = Utils.getBit(rand.tapes[2], rand.pos);

        out[0] = (in1[0] & in2[1]) ^ (in1[1] & in2[0]) ^ (in1[0] & in2[0]) ^ r0 ^ r1;
        out[1] = (in1[1] & in2[2]) ^ (in1[2] & in2[1]) ^ (in1[1] & in2[1]) ^ r1 ^ r2;
        out[2] = (in1[2] & in2[0]) ^ (in1[0] & in2[2]) ^ (in1[2] & in2[2]) ^ r2 ^ r0;

        Utils.setBit(views[0].communicatedBits, rand.pos, (byte)out[0]);
        Utils.setBit(views[1].communicatedBits, rand.pos, (byte)out[1]);
        Utils.setBit(views[2].communicatedBits, rand.pos, (byte)out[2]);

        rand.pos++;
    }

    private void mpc_xor(int[] state, int[] in, int players)
    {
        for (int i = 0, count = stateSizeWords * players; i < count; ++i)
        {
            state[players * stateSizeWords + i] ^= in[i];           
        }
    }

    private void mpc_matrix_mul(int[] output, int outputOffset, int[] state, int stateOffset,
        int[] matrix, int matrixOffset,  int players)
    {
        for (int player = 0; player < players; player++)
        {
            matrix_mul_offset(output, outputOffset + player * stateSizeWords,
                             state, stateOffset + player * stateSizeWords,
                             matrix, matrixOffset);
        }
    }

    /* Compute the XOR of in with the first state vectors. */
    private void mpc_xor_constant(int[] state, int stateOffset, int[] in, int inOffset, int len)
    {
        for (int i = 0; i < len; i++)
        {
            state[i + stateOffset] ^= in[i + inOffset];
        }
    }


    private boolean createRandomTape(byte[] seed, int seedOffset, byte[] salt, int roundNumber, int playerNumber, byte[] tape, int tapeLen)
    {
        if (tapeLen < digestSizeBytes)
        {
            return false;
        }

        /* Hash the seed and a constant, store the result in tape. */
        digest.update((byte) 2);
        digest.update(seed, seedOffset, seedSizeBytes);
        digest.doFinal(tape, 0, digestSizeBytes);
//        System.out.println("tape: " + Hex.toHexString(tape));

        /* Expand the hashed seed, salt, round and player indices, and output
         * length to create the tape. */
        digest.update(tape, 0, digestSizeBytes); // Hash the hashed seed
        digest.update(salt, 0, saltSizeBytes);
        digest.update(Pack.intToLittleEndian(roundNumber), 0, 2);
        digest.update(Pack.intToLittleEndian(playerNumber), 0, 2);
        digest.update(Pack.intToLittleEndian(tapeLen), 0, 2);
        digest.doFinal(tape, 0, tapeLen);

        return true;
    }

    private byte[] computeSeeds(int[] privateKey, int[] publicKey, int[] plaintext, byte[] message)
    {
        byte[] allSeeds = new byte[seedSizeBytes * (numMPCParties * numMPCRounds) + saltSizeBytes];
        byte[] temp = new byte[PICNIC_MAX_LOWMC_BLOCK_SIZE];

        updateDigest(privateKey, temp);
        digest.update(message, 0, message.length);
        updateDigest(publicKey, temp);
        updateDigest(plaintext, temp);
        digest.update(Pack.intToLittleEndian(stateSizeBits), 0, 2);

        // Derive the N*T seeds + 1 salt
        digest.doFinal(allSeeds, 0, seedSizeBytes * (numMPCParties * numMPCRounds) + saltSizeBytes);

        return allSeeds;
    }

    private boolean sign_picnic3(int[] privateKey, int[] pubKey, int[] plaintext, byte[] message, Signature2 sig)
    {
        byte[] saltAndRoot = new byte[saltSizeBytes + seedSizeBytes];
        computeSaltAndRootSeed(saltAndRoot, privateKey, pubKey, plaintext, message);

        byte[] root = Arrays.copyOfRange(saltAndRoot, saltSizeBytes, saltAndRoot.length);
        sig.salt = Arrays.copyOfRange(saltAndRoot, 0, saltSizeBytes);

        Tree iSeedsTree = new Tree(this, numMPCRounds, seedSizeBytes);
        iSeedsTree.generateSeeds(root, sig.salt, 0);

        byte[][] iSeeds = iSeedsTree.getLeaves();
        int iSeedsOffset = iSeedsTree.getLeavesOffset();

        Tape[] tapes = new Tape[numMPCRounds];
        Tree[] seeds = new Tree[numMPCRounds];
        for (int t = 0; t < numMPCRounds; t++)
        {
            tapes[t] = new Tape(this);

            seeds[t] = new Tree(this, numMPCParties, seedSizeBytes);
            seeds[t].generateSeeds(iSeeds[t + iSeedsOffset], sig.salt, t);
            createRandomTapes(tapes[t], seeds[t].getLeaves(), seeds[t].getLeavesOffset(), sig.salt, t);
        }

        byte[][] inputs = new byte[numMPCRounds][stateSizeWords * 4];
        byte[] auxBits = new byte[MAX_AUX_BYTES];
        for (int t = 0; t < numMPCRounds; t++)
        {
            tapes[t].computeAuxTape(inputs[t]);
        }

        /* Commit to seeds and aux bits */
        byte[][][] C = new byte[numMPCRounds][numMPCParties][digestSizeBytes];
        for (int t = 0; t < numMPCRounds; t++)
        {
            for (int j = 0; j < numMPCParties - 1; j++)
            {
                commit(C[t][j], seeds[t].getLeaf(j), null, sig.salt, t, j);
            }
            int last = numMPCParties - 1;
            getAuxBits(auxBits, tapes[t]);
            commit(C[t][last], seeds[t].getLeaf(last), auxBits, sig.salt, t, last);
        }

        /* Simulate the online phase of the MPC */
        Msg[] msgs = new Msg[numMPCRounds];
        int[] tmp_shares = new int[stateSizeBits];
        for (int t = 0; t < numMPCRounds; t++)
        {
            msgs[t] = new Msg(this);
            int[] maskedKey = Pack.littleEndianToInt(inputs[t], 0, stateSizeWords);
            xor_array(maskedKey, maskedKey, privateKey, 0);
            int rv = simulateOnline(maskedKey, tapes[t], tmp_shares, msgs[t], plaintext, pubKey);
            if (rv != 0)
            {
                LOG.fine("MPC simulation failed, aborting signature");
                return false;
            }
            Pack.intToLittleEndian(maskedKey, inputs[t], 0);
        }

        /* Commit to the commitments and views */
        byte[][] Ch = new byte[numMPCRounds][digestSizeBytes];
        byte[][] Cv = new byte[numMPCRounds][digestSizeBytes];
        for (int t = 0; t < numMPCRounds; t++)
        {
            commit_h(Ch[t], C[t]);
            commit_v(Cv[t], inputs[t], msgs[t]);
        }

        /* Create a Merkle tree with Cv as the leaves */
        Tree treeCv = new Tree(this, numMPCRounds, digestSizeBytes);
        treeCv.buildMerkleTree(Cv, sig.salt);

        /* Compute the challenge; two lists of integers */
        sig.challengeC = new int[numOpenedRounds];
        sig.challengeP = new int[numOpenedRounds];
        sig.challengeHash = new byte[digestSizeBytes];
        HCP(sig.challengeHash, sig.challengeC, sig.challengeP, Ch, treeCv.nodes[0], sig.salt, pubKey, plaintext, message);

        /* Send information required for checking commitments with Merkle tree.
         * The commitments the verifier will be missing are those not in challengeC. */
        int missingLeavesSize = numMPCRounds - numOpenedRounds;
        int[] missingLeaves = getMissingLeavesList(sig.challengeC);
        int[] cvInfoLen = new int[1];
        sig.cvInfo = treeCv.openMerkleTree(missingLeaves, missingLeavesSize, cvInfoLen);
        sig.cvInfoLen = cvInfoLen[0];

        /* Reveal iSeeds for unopned rounds, those in {0..T-1} \ ChallengeC. */
        sig.iSeedInfo = new byte[numMPCRounds * seedSizeBytes];
        sig.iSeedInfoLen = iSeedsTree.revealSeeds(sig.challengeC, numOpenedRounds,
                sig.iSeedInfo, numMPCRounds * seedSizeBytes);


        /* Assemble the proof */
        sig.proofs = new Signature2.Proof2[numMPCRounds];
        for (int t = 0; t < numMPCRounds; t++)
        {
            if (contains(sig.challengeC, numOpenedRounds, t))
            {
                sig.proofs[t] = new Signature2.Proof2(this);
                int P_index = indexOf(sig.challengeC, numOpenedRounds, t);

                int[] hideList = new int[1];
                hideList[0] = sig.challengeP[P_index];
                sig.proofs[t].seedInfo = new byte[numMPCParties * seedSizeBytes];
                sig.proofs[t].seedInfoLen = seeds[t].revealSeeds(hideList, 1, sig.proofs[t].seedInfo, numMPCParties * seedSizeBytes);

                int last = numMPCParties - 1;
                if (sig.challengeP[P_index] != last)
                {
                    getAuxBits(sig.proofs[t].aux, tapes[t]);
                }

                System.arraycopy(inputs[t], 0, sig.proofs[t].input, 0, stateSizeBytes);
                System.arraycopy(msgs[t].msgs[sig.challengeP[P_index]], 0, sig.proofs[t].msgs, 0, andSizeBytes);
                System.arraycopy(C[t][sig.challengeP[P_index]], 0, sig.proofs[t].C, 0, digestSizeBytes);
            }
        }
        return true;
    }

    static int indexOf(int[] list, int len, int value)
    {
        for (int i = 0; i < len; i++)
        {
            if (list[i] == value)
            {
                return i;
            }
        }
        return -1;
    }

    private int[] getMissingLeavesList(int[] challengeC)
    {
        int missingLeavesSize = numMPCRounds - numOpenedRounds;
        int[] missingLeaves = new int[missingLeavesSize];
        int pos = 0;

        for (int i = 0; i < numMPCRounds; i++)
        {
            if (!contains(challengeC, numOpenedRounds, i))
            {
                missingLeaves[pos] = i;
                pos++;
            }
        }

        return missingLeaves;
    }

    private void HCP(byte[] challengeHash, int[] challengeC, int[] challengeP, byte[][] Ch,
                    byte[] hCv, byte[] salt, int[] pubKey, int[] plaintext, byte[] message)
    {
//        assert(numOpenedRounds < numMPCRounds);

        for (int t = 0; t < numMPCRounds; t++)
        {
            digest.update(Ch[t], 0, digestSizeBytes);
        }

        byte[] temp = new byte[PICNIC_MAX_LOWMC_BLOCK_SIZE];
        
        digest.update(hCv, 0,  digestSizeBytes);
        digest.update(salt, 0, saltSizeBytes);
        updateDigest(pubKey, temp);
        updateDigest(plaintext, temp);
        digest.update(message, 0, message.length);
        digest.doFinal(challengeHash, 0, digestSizeBytes);

        if((challengeC != null) && (challengeP != null))
        {
            expandChallengeHash(challengeHash, challengeC, challengeP);
        }
    }

    static int bitsToChunks(int chunkLenBits, byte[] input, int inputLen, int[] chunks)
    {
        if (chunkLenBits > inputLen * 8)
        {
            return 0;
        }

        int chunkCount = (inputLen * 8) / chunkLenBits;

        for (int i = 0; i < chunkCount; i++)
        {
            chunks[i] = 0;
            for (int j = 0; j < chunkLenBits; j++)
            {
                chunks[i] += Utils.getBit(input, i * chunkLenBits + j) << j;
//                assert(chunks[i] < (1 << chunkLenBits));
            }
        }

        return chunkCount;
    }

    static int appendUnique(int[] list, int value, int position)
    {
        if (position == 0)
        {
            list[position] = value;
            return position + 1;
        }

        for (int i = 0; i < position; i++)
        {
            if (list[i] == value)
            {
                return position;
            }
        }
        list[position] = value;
        return position + 1;
    }

    private void expandChallengeHash(byte[] challengeHash, int[] challengeC, int[] challengeP)
    {
        // Populate C
        int bitsPerChunkC = Utils.ceil_log2(numMPCRounds);
        int bitsPerChunkP = Utils.ceil_log2(numMPCParties);
        int[] chunks = new int[digestSizeBytes * 8 / Math.min(bitsPerChunkC, bitsPerChunkP)];
        byte[] h = new byte[MAX_DIGEST_SIZE];

        System.arraycopy(challengeHash, 0, h, 0, digestSizeBytes);

        int countC = 0;
        while (countC < numOpenedRounds)
        {
            int numChunks = bitsToChunks(bitsPerChunkC, h, digestSizeBytes, chunks);
            for (int i = 0; i < numChunks; i++)
            {
                if (chunks[i] < numMPCRounds)
                {
                    countC = appendUnique(challengeC, chunks[i], countC);
                }
                if (countC == numOpenedRounds)
                {
                    break;
                }
            }

            digest.update((byte) 1);
            digest.update(h, 0, digestSizeBytes);
            digest.doFinal(h, 0, digestSizeBytes);
        }

        // Note that we always compute h = H(h) after setting C
        int countP = 0;

        while (countP < numOpenedRounds)
        {
            int numChunks = bitsToChunks(bitsPerChunkP, h, digestSizeBytes, chunks);
            for (int i = 0; i < numChunks; i++)
            {
                if (chunks[i] < numMPCParties)
                {
                    challengeP[countP] = chunks[i];
                    countP++;
                }
                if (countP == numOpenedRounds)
                {
                    break;
                }
            }

            digest.update((byte) 1);
            digest.update(h, 0, digestSizeBytes);
            digest.doFinal(h, 0, digestSizeBytes);
        }
    }

    private void commit_h(byte[] digest_arr, byte[][] C)
    {
        for (int i = 0; i < numMPCParties; i++)
        {
            digest.update(C[i], 0, digestSizeBytes);
        }
        digest.doFinal(digest_arr, 0, digestSizeBytes);
    }

    private void commit_v(byte[] digest_arr, byte[] input, Msg msg)
    {
        digest.update(input, 0, stateSizeBytes);
        for (int i = 0; i < numMPCParties; i++)
        {
            int msgs_size = Utils.numBytes(msg.pos);
            digest.update(msg.msgs[i], 0, msgs_size);
        }
        digest.doFinal(digest_arr, 0, digestSizeBytes);
    }

    private int simulateOnline(int[] maskedKey, Tape tape, int[] tmp_shares,
                              Msg msg, int[] plaintext, int[] pubKey)
    {
        int ret = 0;
        int[] roundKey = new int[LOWMC_MAX_WORDS];
        int[] state = new int[LOWMC_MAX_WORDS];

        KMatricesWithPointer current = lowmcConstants.KMatrix(this,0);
        matrix_mul(roundKey, maskedKey, current.getData(), current.getMatrixPointer()); // roundKey = maskedKey * KMatrix[0]
        xor_array(state, roundKey, plaintext, 0);      // state = plaintext + roundKey

        for (int r = 1; r <= numRounds; r++)
        {
            tapesToWords(tmp_shares, tape);
            mpc_sbox(state, tmp_shares, tape, msg);

            current = lowmcConstants.LMatrix(this, r - 1);
            matrix_mul(state, state, current.getData(), current.getMatrixPointer()); // state = state * LMatrix (r-1)

            current = lowmcConstants.RConstant(this,r - 1);
            xor_array(state, state, current.getData(), current.getMatrixPointer());  // state += RConstant

            current = lowmcConstants.KMatrix(this, r);
            matrix_mul(roundKey, maskedKey, current.getData(), current.getMatrixPointer());
            xor_array(state, roundKey, state, 0);      // state += roundKey
        }

        if(!(subarrayEquals(state, pubKey, stateSizeWords)))
        {
            ret = -1;
        }

        return ret;
    }

    private void createRandomTapes(Tape tape, byte[][] seeds, int seedsOffset, byte[] salt, int t)
    {
        int tapeSizeBytes = 2 * andSizeBytes;
        for (int i = 0; i < numMPCParties; i++)
        {
            digest.update(seeds[i + seedsOffset], 0, seedSizeBytes);
            digest.update(salt, 0, saltSizeBytes);
            digest.update(Pack.intToLittleEndian(t), 0, 2);
            digest.update(Pack.intToLittleEndian(i), 0, 2);
            digest.doFinal(tape.tapes[i], 0, tapeSizeBytes);
        }
    }

    private static boolean subarrayEquals(byte[] a, byte[] b, int length)
    {
        if (a.length < length || b.length < length)
        {
            return false;
        }

        for (int i = 0; i < length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    private static boolean subarrayEquals(int[] a, int[] b, int length)
    {
        if (a.length < length || b.length < length)
        {
            return false;
        }

        for (int i = 0; i < length; i++)
        {
            if(a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    static int extend(int bit)
    {
        return ~(bit - 1);
    }

    private void wordToMsgs(int w, Msg msg)
    {
        for (int i = 0; i < numMPCParties; i++)
        {
            int w_i = Utils.getBit(w, i);
            Utils.setBit(msg.msgs[i], msg.pos, (byte)w_i);            
        }
        msg.pos++;
    }

    private int mpc_AND(int a, int b, int mask_a, int mask_b, Tape tape, Msg msg)
    {
        int and_helper = tape.tapesToWord();   // The special mask value setup during preprocessing for each AND gate
        int s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper;

        if (msg.unopened >= 0)
        {
            int unopenedPartyBit = Utils.getBit(msg.msgs[msg.unopened], msg.pos);
            s_shares = Utils.setBit(s_shares, msg.unopened, unopenedPartyBit);
        }

        // Broadcast each share of s
        wordToMsgs(s_shares, msg);
        return Utils.parity16(s_shares) ^ (a & b);
    }

    private void mpc_sbox(int[] state, int[] state_masks, Tape tape, Msg msg)
    {
        for (int i = 0; i < numSboxes * 3; i += 3)
        {
            int a = Utils.getBitFromWordArray(state, i + 2);
            int mask_a = state_masks[i + 2];

            int b = Utils.getBitFromWordArray(state, i + 1);
            int mask_b = state_masks[i + 1];

            int c = Utils.getBitFromWordArray(state, i);
            int mask_c = state_masks[i];

            int ab = mpc_AND(a, b, mask_a, mask_b, tape, msg);
            int bc = mpc_AND(b, c, mask_b, mask_c, tape, msg);
            int ca = mpc_AND(c, a, mask_c, mask_a, tape, msg);

            int d = a ^ bc;
            int e = a ^ b ^ ca;
            int f = a ^ b ^ c ^ ab;

            Utils.setBitInWordArray(state, i + 2, d);
            Utils.setBitInWordArray(state, i + 1, e);
            Utils.setBitInWordArray(state, i, f);
        }
    }

    protected void aux_mpc_sbox(int[] in, int[] out, Tape tape)
    {
        for (int i = 0; i < numSboxes * 3; i += 3)
        {
            int a = Utils.getBitFromWordArray(in, i + 2);
            int b = Utils.getBitFromWordArray(in, i + 1);
            int c = Utils.getBitFromWordArray(in, i);

            int d = Utils.getBitFromWordArray(out, i + 2);
            int e = Utils.getBitFromWordArray(out, i + 1);
            int f = Utils.getBitFromWordArray(out, i);

            int fresh_output_mask_ab = f ^ a ^ b ^ c;
            int fresh_output_mask_bc = d ^ a;
            int fresh_output_mask_ca = e ^ a ^ b;

            aux_mpc_AND(a, b, fresh_output_mask_ab, tape);
            aux_mpc_AND(b, c, fresh_output_mask_bc, tape);
            aux_mpc_AND(c, a, fresh_output_mask_ca, tape);
        }
    }

    private void aux_mpc_AND(int mask_a, int mask_b, int fresh_output_mask, Tape tape)
    {
        int lastParty = numMPCParties - 1;
        int and_helper = tape.tapesToWord();
        and_helper = Utils.parity16(and_helper) ^ Utils.getBit(tape.tapes[lastParty],tape.pos - 1);
        int aux_bit = (mask_a & mask_b) ^ and_helper ^ fresh_output_mask;
        Utils.setBit(tape.tapes[lastParty], tape.pos - 1, (byte) (aux_bit & 0xff));
    }

    private boolean contains(int[] list, int len, int value)
    {
        for (int i = 0; i < len; i++)
        {
            if (list[i] == value)
            {
                return true;
            }
        }
        return false;
    }

    private void tapesToWords(int[] shares, Tape tape)
    {
        for (int w = 0; w < stateSizeBits; w++)
        {
            shares[w] = tape.tapesToWord();
        }
    }

    private void getAuxBits(byte[] output, Tape tape)
    {
        byte[] lastTape = tape.tapes[numMPCParties - 1];
        int n = stateSizeBits, pos = 0, tapePos = 0;

        for(int j = 0; j < numRounds; j++)
        {
            tapePos += n;

            for(int i = 0; i < n; i++)
            {
                Utils.setBit(output, pos++, Utils.getBit(lastTape, tapePos++));
            }
        }
    }

    private void commit(byte[] digest_arr, byte[] seed, byte[] aux, byte[] salt, int t, int j)
    {
        /* Compute C[t][j];  as digest = H(seed||[aux]) aux is optional */
        digest.update(seed, 0, seedSizeBytes);
        if (aux != null)
        {
            digest.update(aux, 0, andSizeBytes);
        }
        digest.update(salt, 0, saltSizeBytes);
        digest.update(Pack.intToLittleEndian(t), 0, 2);
        digest.update(Pack.intToLittleEndian(j), 0, 2);
        digest.doFinal(digest_arr, 0, digestSizeBytes);
    }

    private void computeSaltAndRootSeed(byte[] saltAndRoot, int[] privateKey, int[] pubKey, int[] plaintext, byte[] message)
    {
        byte[] temp = new byte[PICNIC_MAX_LOWMC_BLOCK_SIZE];

        // init done in constructor
        updateDigest(privateKey, temp);
        digest.update(message, 0, message.length);
        updateDigest(pubKey, temp);
        updateDigest(plaintext, temp);
        Pack.shortToLittleEndian((short)stateSizeBits, temp, 0);
        digest.update(temp, 0, 2);
        digest.doFinal(saltAndRoot, 0, saltAndRoot.length);
    }

    private void updateDigest(int[] block, byte[] temp)
    {
        Pack.intToLittleEndian(block, temp, 0);
        digest.update(temp, 0, stateSizeBytes);
    }

    static boolean is_picnic3(int params)
    {
        return params == 7/*Picnic3_L1*/
            || params == 8/*Picnic3_L3*/
            || params == 9/*Picnic3_L5*/;
    }

    //todo return int;
    public void crypto_sign_keypair(byte[] pk, byte[] sk, SecureRandom random)
    {
        // set array sizes
        byte[] plaintext_bytes = new byte[stateSizeWords * 4];
        byte[] ciphertext_bytes = new byte[stateSizeWords * 4];
        byte[] data_bytes = new byte[stateSizeWords * 4];

        picnic_keygen(plaintext_bytes, ciphertext_bytes, data_bytes, random);
        picnic_write_public_key(ciphertext_bytes, plaintext_bytes, pk);
        picnic_write_private_key(data_bytes, ciphertext_bytes, plaintext_bytes, sk);
    }

    private int picnic_write_private_key(byte[] data, byte[] ciphertext, byte[] plaintext, byte[] buf)
    {
        int bytesRequired = 1 + 3 * stateSizeBytes;
        if (buf.length < bytesRequired)
        {
            LOG.fine("Failed writing private key!");
            return -1;
        }
        buf[0] = (byte) parameters;
        System.arraycopy(data, 0, buf, 1, stateSizeBytes);
        System.arraycopy(ciphertext, 0, buf, 1 + stateSizeBytes, stateSizeBytes);
        System.arraycopy(plaintext, 0, buf, 1 + 2 * stateSizeBytes, stateSizeBytes);
        return bytesRequired;
    }

    private int picnic_write_public_key(byte[] ciphertext, byte[] plaintext, byte[] buf)
    {
        int bytesRequired = 1 + 2 * stateSizeBytes;
        if (buf.length < bytesRequired)
        {
            LOG.fine("Failed writing public key!");
            return -1;
        }
        buf[0] = (byte) parameters;
        System.arraycopy(ciphertext, 0, buf, 1, stateSizeBytes);
        System.arraycopy(plaintext, 0, buf,1 + stateSizeBytes, stateSizeBytes);
        return bytesRequired;

    }

    // todo use object to store pt and ct in public key and data in private key
    private void picnic_keygen(byte[] plaintext_bytes, byte[] ciphertext_bytes, byte[] data_bytes, SecureRandom random)
    {
        int[] data = new int[data_bytes.length/4];
        int[] plaintext = new int[plaintext_bytes.length/4];
        int[] ciphertext = new int[ciphertext_bytes.length/4];

        // generate a private key
        random.nextBytes(data_bytes);
        Pack.littleEndianToInt(data_bytes, 0, data);
        Utils.zeroTrailingBits(data, stateSizeBits);

        // generate a plaintext block
        random.nextBytes(plaintext_bytes);
        Pack.littleEndianToInt(plaintext_bytes, 0, plaintext);
        Utils.zeroTrailingBits(plaintext, stateSizeBits);

        // computer ciphertext
        LowMCEnc(plaintext, ciphertext, data);

        //copy back to byte array
        Pack.intToLittleEndian(data, data_bytes, 0);
        Pack.intToLittleEndian(plaintext, plaintext_bytes, 0);
        Pack.intToLittleEndian(ciphertext, ciphertext_bytes, 0);
    }


    private void LowMCEnc(int[] plaintext, int[] output, int[] key)
    {
        int[] roundKey = new int[LOWMC_MAX_WORDS];

        if (plaintext != (output))
        {
            /* output will hold the intermediate state */
            System.arraycopy(plaintext, 0, output, 0, stateSizeWords);
        }

        KMatricesWithPointer current = lowmcConstants.KMatrix(this,0);
        matrix_mul(roundKey, key, current.getData(), current.getMatrixPointer());

        xor_array(output, output, roundKey, 0);

        for (int r = 1; r <= numRounds; r++)
        {
            current = lowmcConstants.KMatrix(this, r);
            matrix_mul(roundKey, key, current.getData(), current.getMatrixPointer());

            substitution(output);

            current = lowmcConstants.LMatrix(this,r-1);
            matrix_mul(output, output, current.getData(), current.getMatrixPointer());

            current = lowmcConstants.RConstant(this,r-1);
            xor_array(output, output, current.getData(), current.getMatrixPointer());
            xor_array(output, output, roundKey, 0);
        }
    }


    private void substitution(int[] state)
    {
        for (int i = 0; i < numSboxes * 3; i += 3)
        {
            int a = Utils.getBitFromWordArray(state, i + 2);
            int b = Utils.getBitFromWordArray(state, i + 1);
            int c = Utils.getBitFromWordArray(state, i);

            Utils.setBitInWordArray(state, i + 2, (a ^ (b & c)));
            Utils.setBitInWordArray(state, i + 1, (a ^ b ^ (a & c)));
            Utils.setBitInWordArray(state, i,  (a ^ b ^ c ^ (a & b)));
        }
    }

    private void xor_three(int[] output, int[] in1, int[] in2, int[] in3)
    {
        for(int i = 0; i < stateSizeWords; i++)
        {
            output[i] = in1[i] ^ in2[i] ^ in3[i];
        }
    }

    protected void xor_array(int[] out, int[] in1, int[] in2, int in2_offset)
    {
        for (int i = 0; i < stateSizeWords; i++)
        {
            out[i] = in1[i] ^ in2[i + in2_offset];
        }
    }

    protected void matrix_mul(int[] output, int[] state, int[] matrix, int matrixOffset)
    {
        matrix_mul_offset(output, 0, state, 0, matrix, matrixOffset);
    }

    protected void matrix_mul_offset(int[] output, int outputOffset,
                                     int[] state, int stateOffset,
                                     int[] matrix, int matrixOffset)
    {
        // Use temp to correctly handle the case when state = output
        int prod;
        int[] temp = new int[LOWMC_MAX_WORDS];
        temp[stateSizeWords-1] = 0;
        int wholeWords = stateSizeBits/WORD_SIZE_BITS;
        int unusedStateBits = stateSizeWords * WORD_SIZE_BITS - stateSizeBits;

        // The final word mask, with bits reversed within each byte
        int partialWordMask = -1 >>> unusedStateBits;
        partialWordMask = Bits.bitPermuteStepSimple(partialWordMask, 0x55555555, 1);
        partialWordMask = Bits.bitPermuteStepSimple(partialWordMask, 0x33333333, 2);
        partialWordMask = Bits.bitPermuteStepSimple(partialWordMask, 0x0F0F0F0F, 4);

        for (int i = 0; i < stateSizeBits; i++)
        {
            prod = 0;
            for (int j = 0; j < wholeWords; j++)
            {
                int index = i * stateSizeWords + j;
                prod ^= state[stateOffset + j] &
                        matrix[matrixOffset + index];
            }
            if (unusedStateBits > 0)
            {
                int index = i * stateSizeWords + wholeWords;
                prod ^= state[stateOffset + wholeWords] &
                        matrix[matrixOffset + index] &
                        partialWordMask;
            }
            Utils.setBit(temp, i, Utils.parity32(prod));
        }

        System.arraycopy(temp, 0, output, outputOffset, stateSizeWords);
    }
}
