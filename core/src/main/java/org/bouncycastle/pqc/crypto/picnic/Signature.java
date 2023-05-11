package org.bouncycastle.pqc.crypto.picnic;

class Signature
{
    final byte[] challengeBits;
    final byte[] salt;
    final Proof[] proofs;
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
        final byte[] seed1;
        final byte[] seed2;
        final int[] inputShare;     // Input share of the party which does not derive it from the seed (not included if challenge is 0)
        final byte[] communicatedBits;
        final byte[] view3Commitment;
        final byte[] view3UnruhG;     // we include the max length, but we will only serialize the bytes we use

        Proof(PicnicEngine engine)
        {
            seed1 = new byte[engine.seedSizeBytes];
            seed2 = new byte[engine.seedSizeBytes];
            inputShare = new int[engine.stateSizeWords];
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
