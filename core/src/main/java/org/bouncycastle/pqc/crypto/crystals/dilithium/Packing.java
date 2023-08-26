package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.util.Arrays;

class Packing
{

    static byte[] packPublicKey(PolyVecK t1, DilithiumEngine engine)
    {
        byte[] out = new byte[engine.getCryptoPublicKeyBytes() - DilithiumEngine.SeedBytes];

        for (int i = 0; i < engine.getDilithiumK(); ++i)
        {
            System.arraycopy(t1.getVectorIndex(i).polyt1Pack(), 0, out, i * DilithiumEngine.DilithiumPolyT1PackedBytes, DilithiumEngine.DilithiumPolyT1PackedBytes);
        }
        return out;
    }

    static PolyVecK unpackPublicKey(PolyVecK t1, byte[] publicKey, DilithiumEngine engine)
    {
        int i;

        for (i = 0; i < engine.getDilithiumK(); ++i)
        {
            t1.getVectorIndex(i).polyt1Unpack(Arrays.copyOfRange(publicKey, i * DilithiumEngine.DilithiumPolyT1PackedBytes, DilithiumEngine.SeedBytes + (i + 1) * DilithiumEngine.DilithiumPolyT1PackedBytes));
        }
        return t1;
    }

    static byte[][] packSecretKey(byte[] rho, byte[] tr, byte[] key, PolyVecK t0, PolyVecL s1, PolyVecK s2, DilithiumEngine engine)
    {
        byte[][] out = new byte[6][];

        out[0] = rho;
        out[1] = key;
        out[2] = tr;

        out[3] = new byte[engine.getDilithiumL() * engine.getDilithiumPolyEtaPackedBytes()];
        for (int i = 0; i < engine.getDilithiumL(); ++i)
        {
            s1.getVectorIndex(i).polyEtaPack(out[3], i * engine.getDilithiumPolyEtaPackedBytes());
        }

        out[4] = new byte[engine.getDilithiumK() * engine.getDilithiumPolyEtaPackedBytes()];
        for (int i = 0; i < engine.getDilithiumK(); ++i)
        {
            s2.getVectorIndex(i).polyEtaPack(out[4], i * engine.getDilithiumPolyEtaPackedBytes());
        }

        out[5] = new byte[engine.getDilithiumK() * DilithiumEngine.DilithiumPolyT0PackedBytes];
        for (int i = 0; i < engine.getDilithiumK(); ++i)
        {
            t0.getVectorIndex(i).polyt0Pack(out[5], i * DilithiumEngine.DilithiumPolyT0PackedBytes);
        }
        return out;
    }

    /**
     * @param t0
     * @param s1
     * @param s2
     * @param engine
     * @return Byte matrix where byte[0] = rho, byte[1] = tr, byte[2] = key
     */

    static void unpackSecretKey(PolyVecK t0, PolyVecL s1, PolyVecK s2, byte[] t0Enc, byte[] s1Enc, byte[] s2Enc, DilithiumEngine engine)
    {
        for (int i = 0; i < engine.getDilithiumL(); ++i)
        {
            s1.getVectorIndex(i).polyEtaUnpack(s1Enc, i * engine.getDilithiumPolyEtaPackedBytes());
        }

        for (int i = 0; i < engine.getDilithiumK(); ++i)
        {
            s2.getVectorIndex(i).polyEtaUnpack(s2Enc, i * engine.getDilithiumPolyEtaPackedBytes());
        }

        for (int i = 0; i < engine.getDilithiumK(); ++i)
        {
            t0.getVectorIndex(i).polyt0Unpack(t0Enc, i * DilithiumEngine.DilithiumPolyT0PackedBytes);
        }
    }

    static byte[] packSignature(byte[] c, PolyVecL z, PolyVecK h, DilithiumEngine engine)
    {
        int i, j, k, end = 0;
        byte[] outBytes = new byte[engine.getCryptoBytes()];

        System.arraycopy(c, 0, outBytes, 0, engine.getDilithiumCTilde());
        end += engine.getDilithiumCTilde();

        for (i = 0; i < engine.getDilithiumL(); ++i)
        {
            System.arraycopy(z.getVectorIndex(i).zPack(), 0, outBytes, end + i * engine.getDilithiumPolyZPackedBytes(), engine.getDilithiumPolyZPackedBytes());
        }
        end += engine.getDilithiumL() * engine.getDilithiumPolyZPackedBytes();

        for (i = 0; i < engine.getDilithiumOmega() + engine.getDilithiumK(); ++i)
        {
            outBytes[end + i] = 0;
        }

        k = 0;
        for (i = 0; i < engine.getDilithiumK(); ++i)
        {
            for (j = 0; j < DilithiumEngine.DilithiumN; ++j)
            {
                if (h.getVectorIndex(i).getCoeffIndex(j) != 0)
                {
                    outBytes[end + k++] = (byte)j;
                }
            }
            outBytes[end + engine.getDilithiumOmega() + i] = (byte)k;
        }

        return outBytes;

    }

    static boolean unpackSignature(PolyVecL z, PolyVecK h, byte[] sig, DilithiumEngine engine)
    {
        int i, j, k;

        int end = engine.getDilithiumCTilde();
        for (i = 0; i < engine.getDilithiumL(); ++i)
        {
            z.getVectorIndex(i).zUnpack(Arrays.copyOfRange(sig, end + i * engine.getDilithiumPolyZPackedBytes(), end + (i + 1) * engine.getDilithiumPolyZPackedBytes()));
        }
        end += engine.getDilithiumL() * engine.getDilithiumPolyZPackedBytes();

        k = 0;
        for (i = 0; i < engine.getDilithiumK(); ++i)
        {
            for (j = 0; j < DilithiumEngine.DilithiumN; ++j)
            {
                h.getVectorIndex(i).setCoeffIndex(j, 0);
            }

            if ((sig[end + engine.getDilithiumOmega() + i] & 0xFF) < k || (sig[end + engine.getDilithiumOmega() + i] & 0xFF) > engine.getDilithiumOmega())
            {
                return false;
            }

            for (j = k; j < (sig[end + engine.getDilithiumOmega() + i] & 0xFF); ++j)
            {
                if (j > k && (sig[end + j] & 0xFF) <= (sig[end + j - 1] & 0xFF))
                {
                    return false;
                }
                h.getVectorIndex(i).setCoeffIndex((sig[end + j] & 0xFF), 1);
            }

            k = (int)(sig[end + engine.getDilithiumOmega() + i]);
        }
        for (j = k; j < engine.getDilithiumOmega(); ++j)
        {
            if ((sig[end + j] & 0xFF) != 0)
            {                    
                return false;
            }
        }
        return true;
    }

}
