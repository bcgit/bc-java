package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class CrossEngine
{
    private final SHAKEDigest digest;
    private final int securityLevel;

    public CrossEngine(int securityLevel)
    {
        this.securityLevel = securityLevel;
        if (securityLevel <= 128)
        {
            digest = new SHAKEDigest(128);
        }
        else
        {
            digest = new SHAKEDigest(256);
        }
    }

    public void init(byte[] seed, int seedLen, int dsc)
    {
        init(seed, 0, seedLen, dsc);
    }

    public void init(byte[] seed, int seedOff, int seedLen, int dsc)
    {
        digest.reset();
        digest.update(seed, seedOff, seedLen);
        byte[] dscBytes = new byte[]{
            (byte)(dsc & 0xFF),
            (byte)((dsc >> 8) & 0xFF)
        };
        digest.update(dscBytes, 0, 2);
    }

    public void randomBytes(byte[] out, int outLen)
    {
        randomBytes(out, 0, outLen);
    }

    public void randomBytes(byte[] out, int outOff, int outLen)
    {
        digest.doOutput(out, outOff, outLen);
    }

    // Helper function to round up to nearest multiple
    public static int roundUp(int amount, int roundAmt)
    {
        return ((amount + roundAmt - 1) / roundAmt) * roundAmt;
    }

    // Calculate bits needed to represent a number
    public static int bitsToRepresent(int n)
    {
        if (n == 0)
        {
            return 1;
        }
        return 32 - Integer.numberOfLeadingZeros(n);
    }

    // Expand public key for RSDP variant
    public void expandPk(CrossParameters params, byte[][] V_tr, byte[] seedPk)
    {
        int dsc = 0 + (3 * params.getT() + 2); // CSPRNG_DOMAIN_SEP_CONST is 0
        init(seedPk, seedPk.length, dsc);
        csprngFpMat(V_tr, params);
    }

    // Expand public key for RSDPG variant
    public void expandPk(CrossParameters params, short[][] V_tr, byte[][] W_mat, byte[] seedPk)
    {
        int dsc = 0 + (3 * params.getT() + 2); // CSPRNG_DOMAIN_SEP_CONST is 0
        init(seedPk, seedPk.length, dsc);
        csprngFzMat(W_mat, params);
        csprngFpMat(V_tr, params);
    }

    // Generate FP matrix (8-bit version)
    private void csprngFpMat(byte[][] res, CrossParameters params)
    {
        int rows = params.getK();
        int cols = params.getN() - params.getK();
        int total = rows * cols;
        int bitsForP = bitsToRepresent(params.getP() - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsVCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < params.getP())
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForP; // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
    }

    // Generate FP matrix (16-bit version)
    private void csprngFpMat(short[][] res, CrossParameters params)
    {
        int rows = params.getK();
        int cols = params.getN() - params.getK();
        int total = rows * cols;
        int bitsForP = bitsToRepresent(params.getP() - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsVCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < params.getP())
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (short)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForP; // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
    }

    // Generate FZ matrix (8-bit version)
    private void csprngFzMat(byte[][] res, CrossParameters params)
    {
        int rows = params.getM();
        int cols = params.getN() - params.getM();
        int total = rows * cols;
        int bitsForZ = bitsToRepresent(params.getZ() - 1);
        long mask = (1L << bitsForZ) - 1;
        int bufferSize = roundUp(params.getBitsWCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < params.getZ())
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForZ; // Unsigned right shift
            bitsInSubBuf -= bitsForZ;
        }
    }

    // Generate FZ vector for RSDP variant
    public void csprngFzVec(byte[] res, CrossParameters params)
    {
        int n = params.getN();
        int z = params.getZ();
        int bitsForZ = bitsToRepresent(z - 1);
        long mask = (1L << bitsForZ) - 1;
        int bufferSize = roundUp(params.getBitsNFzCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < n)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < z)
            {
                res[placed] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForZ; // Unsigned right shift
            bitsInSubBuf -= bitsForZ;
        }
    }

    // Generate FZ vector for RSDPG variant
    public void csprngFzInfW(byte[] res, CrossParameters params)
    {
        int m = params.getM();
        int z = params.getZ();
        int bitsForZ = bitsToRepresent(z - 1);
        long mask = (1L << bitsForZ) - 1;
        //TODO: BitsMFzCtRng
        int bufferSize = 0;//roundUp(params.getBitsMFzCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < m)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < z)
            {
                res[placed] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForZ; // Unsigned right shift
            bitsInSubBuf -= bitsForZ;
        }
    }
}
