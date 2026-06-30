package org.bouncycastle.pqc.crypto.aimer;

/**
 * Proof structure for AIMER signature scheme
 */
class Proof
{
    final byte[][] revealPath;           // [AIMER_LOGN][AIMER_SEED_SIZE]
    final byte[] missingCommitment;      // [AIMER_COMMIT_SIZE]
    final byte[] deltaPtBytes;           // [AIM2_NUM_BYTES_FIELD]
    final byte[][] deltaTsBytes;         // [AIMER_L][AIM2_NUM_BYTES_FIELD]
    final byte[] deltaCBytes;            // [AIM2_NUM_BYTES_FIELD]
    final byte[] missingAlphaShareBytes; // [AIM2_NUM_BYTES_FIELD]

    public Proof(AIMerParameters params)
    {
        int fieldBytes = params.getAim2NumBytesField();
        int L = params.getAimerL();

        // Initialize arrays
        this.revealPath = null;//new byte[logN][seedSize];
        this.missingCommitment = null;//new byte[commitSize];
        this.deltaPtBytes = new byte[fieldBytes];
        this.deltaTsBytes = new byte[L][fieldBytes];
        this.deltaCBytes = new byte[fieldBytes];
        this.missingAlphaShareBytes = null;//new byte[fieldBytes];
    }
    /**
     * Constructor that reads proof data from a signature byte array
     *
     * @param params AIMER parameters
     * @param sig    Signature byte array
     * @param sigOff Offset in the signature array where proof data starts
     */
    public Proof(AIMerParameters params, byte[] sig, int sigOff)
    {
        // Calculate sizes from parameters
        int logN = params.getAimerLogN();
        int seedSize = params.getAimerSeedSize();
        int commitSize = params.getAimerCommitSize();
        int fieldBytes = params.getAim2NumBytesField();
        int L = params.getAimerL();

        // Initialize arrays
        this.revealPath = new byte[logN][seedSize];
        this.missingCommitment = new byte[commitSize];
        this.deltaPtBytes = new byte[fieldBytes];
        this.deltaTsBytes = new byte[L][fieldBytes];
        this.deltaCBytes = new byte[fieldBytes];
        this.missingAlphaShareBytes = new byte[fieldBytes];

        // Copy data from signature array
        int offset = sigOff;

        // 1. Copy reveal_path: AIMER_LOGN * AIMER_SEED_SIZE bytes
        for (int i = 0; i < logN; i++)
        {
            System.arraycopy(sig, offset, revealPath[i], 0, seedSize);
            offset += seedSize;
        }

        // 2. Copy missing_commitment: AIMER_COMMIT_SIZE bytes
        System.arraycopy(sig, offset, missingCommitment, 0, commitSize);
        offset += commitSize;

        // 3. Copy delta_pt_bytes: AIM2_NUM_BYTES_FIELD bytes
        System.arraycopy(sig, offset, deltaPtBytes, 0, fieldBytes);
        offset += fieldBytes;

        // 4. Copy delta_ts_bytes: AIMER_L * AIM2_NUM_BYTES_FIELD bytes
        for (int i = 0; i < L; i++)
        {
            System.arraycopy(sig, offset, deltaTsBytes[i], 0, fieldBytes);
            offset += fieldBytes;
        }

        // 5. Copy delta_c_bytes: AIM2_NUM_BYTES_FIELD bytes
        System.arraycopy(sig, offset, deltaCBytes, 0, fieldBytes);
        offset += fieldBytes;

        // 6. Copy missing_alpha_share_bytes: AIM2_NUM_BYTES_FIELD bytes
        System.arraycopy(sig, offset, missingAlphaShareBytes, 0, fieldBytes);
    }

    // Static method to calculate proof size for given parameters
    public static int getByteSize(AIMerParameters params)
    {
        return params.getAimerLogN() * params.getAimerSeedSize() +
            params.getAimerCommitSize() +
            params.getAim2NumBytesField() * (3 + params.getAimerL());  // 3 = deltaPt + deltaC + missingAlphaShare
    }
}