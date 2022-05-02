package org.bouncycastle.pqc.crypto.picnic;

class Signature2
{
    byte[] salt;
    byte[] iSeedInfo;         // Info required to recompute the tree of all initial seeds
    int iSeedInfoLen;
    byte[] cvInfo;            // Info required to check commitments to views (reconstruct Merkle tree)
    int cvInfoLen;
    byte[] challengeHash;
    int[] challengeC;
    int[] challengeP;
    Proof2[] proofs;         // One proof for each online execution the verifier checks

    //todo initialize in engine!
    public Signature2(PicnicEngine engine)
    {
        challengeHash = new byte[engine.digestSizeBytes];
        salt = new byte[PicnicEngine.saltSizeBytes];
        challengeC = new int[engine.numOpenedRounds];
        challengeP = new int[engine.numOpenedRounds];
        proofs = new Proof2[engine.numMPCRounds];
    }
    public static class Proof2
    {
        byte[] seedInfo;          // Information required to compute the tree with seeds of of all opened parties
        int seedInfoLen;         // Length of seedInfo buffer
        byte[] aux;               // Last party's correction bits; NULL if P[t] == N-1
        byte[] C;                 // Commitment to preprocessing step of unopened party
        byte[] input;             // Masked input used in online execution
        byte[] msgs;              // Broadcast messages of unopened party P[t]

        public Proof2(PicnicEngine engine)
        {
            seedInfo = null;
            seedInfoLen = 0;
            C = new byte[engine.digestSizeBytes];
            input = new byte[engine.stateSizeBytes];
            aux = new byte[engine.andSizeBytes];
            msgs = new byte[engine.andSizeBytes];

        }
    }

}



