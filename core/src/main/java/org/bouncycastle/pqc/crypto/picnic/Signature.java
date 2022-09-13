package org.bouncycastle.pqc.crypto.picnic;

class Signature
{
    byte[] challengeBits;
    byte[] salt;
    Proof[] proofs;
    Signature(PicnicEngine engine)
    {
        salt = new byte[PicnicEngine.saltSizeBytes];
        challengeBits = new byte[Utils.numBytes(engine.numMPCRounds * 2)];
        proofs = new Proof[engine.numMPCRounds];
        for (int i = 0; i < proofs.length; i++)
        {
            proofs[i] = new Proof(engine);
        }
    }

    public static class Proof
    {
        byte[] seed1;
        byte[] seed2;
        int[] inputShare;     // Input share of the party which does not derive it from the seed (not included if challenge is 0)
        byte[] communicatedBits;
        byte[] view3Commitment;
        byte[] view3UnruhG;     // we include the max length, but we will only serialize the bytes we use

        Proof(PicnicEngine engine)
        {
            seed1 = new byte[engine.seedSizeBytes];
            seed2 = new byte[engine.seedSizeBytes];
            inputShare = new int[engine.stateSizeBytes];
            communicatedBits = new byte[engine.andSizeBytes];
            view3Commitment = new byte[engine.digestSizeBytes];
            if (engine.UnruhGWithInputBytes > 0)
            {
                view3UnruhG = new byte[engine.UnruhGWithInputBytes];
            }
            else
            {
                view3UnruhG = null;
            }
        }
    }
}
