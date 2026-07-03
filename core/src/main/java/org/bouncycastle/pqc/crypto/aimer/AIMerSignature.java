package org.bouncycastle.pqc.crypto.aimer;

import org.bouncycastle.util.Arrays;

/**
 * AIMER signature structure
 */
class AIMerSignature
{
    final byte[] salt;         // AIMER_SALT_SIZE bytes
    final byte[] h_1;          // AIMER_COMMIT_SIZE bytes
    final byte[] h_2;          // AIMER_COMMIT_SIZE bytes
    final Proof[] proofs;      // AIMER_T proofs

    public AIMerSignature(byte[] sig, AIMerParameters params)
    {
        this.salt = Arrays.copyOf(sig, params.getAimerSaltSize());
        int sigOff = salt.length;
        this.h_1 = Arrays.copyOfRange(sig, sigOff, sigOff + params.getAimerCommitSize());
        sigOff += this.h_1.length;
        this.h_2 = Arrays.copyOfRange(sig, sigOff, sigOff + params.getAimerCommitSize());
        sigOff += this.h_1.length;
        this.proofs = new Proof[params.getAimerT()];
        int proofSize = Proof.getByteSize(params);
        for (int i = 0; i < proofs.length; i++)
        {
            this.proofs[i] = new Proof(params, sig, sigOff);
            sigOff += proofSize;    // advance offset by the size of one proof
        }
    }

    public AIMerSignature(AIMerParameters params)
    {
        this.salt  = new byte[params.getAimerSaltSize()];
        this.h_1  = new byte[params.getAimerCommitSize()];
        this.h_2  = new byte[params.getAimerCommitSize()];
        this.proofs = new Proof[params.getAimerT()];
        for (int i = 0; i < proofs.length; i++)
        {
            this.proofs[i] = new Proof(params);
        }
    }
}
