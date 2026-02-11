package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class MLKEMIndCpa
{
    private static final int SHAKE128_RATE = 168;

    private static final int NUM_MATRIX_BLOCKS =
        (((12 * MLKEMEngine.N / 8) << 12) / MLKEMEngine.Q + SHAKE128_RATE) / SHAKE128_RATE;

    private final MLKEMEngine engine;

    MLKEMIndCpa(MLKEMEngine engine)
    {
        this.engine = engine;
    }

    /**
     * Generates IndCpa Key Pair
     *
     * @return KeyPair where each key is represented as bytes
     */
    byte[][] generateKeyPair(byte[] d)
    {
        int K = engine.getK();

        PolyVec secretKey = new PolyVec(K), publicKey = new PolyVec(K), e = new PolyVec(K);

        // (p, sigma) <- G(d || k)

        byte[] buf = new byte[64];
        MLKEMEngine.hash_G(Arrays.append(d, (byte)K), buf);

        byte[] publicSeed = new byte[32]; // p in docs
        byte[] noiseSeed = new byte[32]; // sigma in docs
        System.arraycopy(buf, 0, publicSeed, 0, 32);
        System.arraycopy(buf, 32, noiseSeed, 0, 32);

        PolyVec[] matrixA = new PolyVec[K];

        for (int i = 0; i < K; i++)
        {
            matrixA[i] = new PolyVec(K);
        }

        generateMatrixA(matrixA, publicSeed, false);

        SHAKEDigest xof = new SHAKEDigest(256);

        byte nonce = 0;
        if (engine.getEta1() == 2)
        {
            for (int i = 0; i < K; i++)
            {
                secretKey.getVectorIndex(i).getNoiseEta2(xof, noiseSeed, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                e.getVectorIndex(i).getNoiseEta2(xof, noiseSeed, nonce++);
            }
        }
        else
        {
            for (int i = 0; i < K; i++)
            {
                secretKey.getVectorIndex(i).getNoiseEta3(xof, noiseSeed, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                e.getVectorIndex(i).getNoiseEta3(xof, noiseSeed, nonce++);
            }
        }

        secretKey.polyVecNtt();

        e.polyVecNtt();

        for (int i = 0; i < K; i++)
        {
            PolyVec.pointwiseAccountMontgomery(publicKey.getVectorIndex(i), matrixA[i], secretKey, engine);
            publicKey.getVectorIndex(i).convertToMont();
        }

        publicKey.addPoly(e);
        publicKey.reducePoly();

        return new byte[][]{ packPublicKey(publicKey, publicSeed), packSecretKey(secretKey) };
    }

    void decrypt(byte[] secretKey, byte[] cipherText, byte[] m)
    {
        int K = engine.getK();

        PolyVec bp = new PolyVec(K), skpv = new PolyVec(K);
        Poly v = new Poly(), mp = new Poly();

        unpackCipherText(bp, v, cipherText, 0);
        unpackSecretKey(skpv, secretKey);

        bp.polyVecNtt();

        PolyVec.pointwiseAccountMontgomery(mp, skpv, bp, engine);

        mp.polyInverseNttToMont();
        mp.subtract(v);
        mp.reduce();
        mp.toMsg(m);
    }

    byte[] encrypt(byte[] publicKeyInput, byte[] msg, byte[] coins)
    {
        int K = engine.getK();

        byte nonce = (byte)0;
        PolyVec sp = new PolyVec(K), pkpv = new PolyVec(K), ep = new PolyVec(K), bp = new PolyVec(K);
        PolyVec[] matrixATransposed = new PolyVec[engine.getK()];
        Poly errorPoly = new Poly(), v = new Poly(), k = new Poly();

        byte[] seed = unpackPublicKey(pkpv, publicKeyInput);

        k.fromMsg(msg);

        for (int i = 0; i < K; i++)
        {
            matrixATransposed[i] = new PolyVec(K);
        }

        generateMatrixA(matrixATransposed, seed, true);

        SHAKEDigest xof = new SHAKEDigest(256);

        if (engine.getEta1() == 2)
        {
            for (int i = 0; i < K; i++)
            {
                sp.getVectorIndex(i).getNoiseEta2(xof, coins, nonce++);
            }
        }
        else
        {
            for (int i = 0; i < K; i++)
            {
                sp.getVectorIndex(i).getNoiseEta3(xof, coins, nonce++);
            }
        }

        for (int i = 0; i < K; i++)
        {
            ep.getVectorIndex(i).getNoiseEta2(xof, coins, nonce++);
        }
        errorPoly.getNoiseEta2(xof, coins, nonce);

        sp.polyVecNtt();

        for (int i = 0; i < K; i++)
        {
            PolyVec.pointwiseAccountMontgomery(bp.getVectorIndex(i), matrixATransposed[i], sp, engine);
        }

        PolyVec.pointwiseAccountMontgomery(v, pkpv, sp, engine);

        bp.polyVecInverseNttToMont();

        v.polyInverseNttToMont();

        bp.addPoly(ep);

        v.add(errorPoly);
        v.add(k);

        bp.reducePoly();
        v.reduce();

        return packCipherText(bp, v);
    }

    private byte[] packCipherText(PolyVec b, Poly v)
    {
        int polyVecCompressedBytes = engine.getPolyVecCompressedBytes();

        byte[] outBuf = new byte[engine.getCipherTextBytes()];
        b.compressPolyVec(outBuf, 0);

        byte[] compressedPoly;
        if (engine.getK() == 4)
        {
            compressedPoly = v.compressPoly160();
        }
        else
        {
            compressedPoly = v.compressPoly128();
        }

        System.arraycopy(compressedPoly, 0, outBuf, polyVecCompressedBytes, engine.getPolyCompressedBytes());
        return outBuf;
    }

    private void unpackCipherText(PolyVec b, Poly v, byte[] cBuf, int cOff)
    {
        b.decompressPolyVec(cBuf, cOff);
        cOff += engine.getPolyVecCompressedBytes();

        if (engine.getK() == 4)
        {
            v.decompressPoly160(cBuf, cOff);
        }
        else
        {
            v.decompressPoly128(cBuf, cOff);
        }
    }

    byte[] packPublicKey(PolyVec publicKeyPolyVec, byte[] seed)
    {
        int indCpaPublicKeyBytes = engine.getPublicKeyBytes();
        int polyVecBytes = engine.getPolyVecBytes();

        byte[] buf = new byte[indCpaPublicKeyBytes];
        publicKeyPolyVec.toBytes(buf, 0);
        System.arraycopy(seed, 0, buf, polyVecBytes, MLKEMEngine.SymBytes);
        return buf;
    }

    byte[] unpackPublicKey(PolyVec publicKeyPolyVec, byte[] publicKey)
    {
        int polyVecBytes = engine.getPolyVecBytes();

        byte[] outputSeed = new byte[MLKEMEngine.SymBytes];
        publicKeyPolyVec.fromBytes(publicKey);
        System.arraycopy(publicKey, polyVecBytes, outputSeed, 0, MLKEMEngine.SymBytes);
        return outputSeed;
    }

    byte[] packSecretKey(PolyVec secretKeyPolyVec)
    {
        byte[] r = new byte[engine.getPolyVecBytes()];
        secretKeyPolyVec.toBytes(r, 0);
        return r;
    }

    void unpackSecretKey(PolyVec secretKeyPolyVec, byte[] secretKey)
    {
        secretKeyPolyVec.fromBytes(secretKey);
    }

    void generateMatrixA(PolyVec[] aMatrix, byte[] seed, boolean transpose)
    {
        int K = engine.getK();
        SHAKEDigest xof = new SHAKEDigest(128);

        byte[] buf = new byte[NUM_MATRIX_BLOCKS * SHAKE128_RATE + 2];
        for (int i = 0; i < K; i++)
        {
            for (int j = 0; j < K; j++)
            {
                xof.reset();

                xof.update(seed, 0, seed.length);

                if (transpose)
                {
                    xof.update((byte)i);
                    xof.update((byte)j);
                }
                else
                {
                    xof.update((byte)j);
                    xof.update((byte)i);
                }

                int buflen = NUM_MATRIX_BLOCKS * SHAKE128_RATE;
                xof.doOutput(buf, 0, buflen);

                int ctr = rejectionSampling(aMatrix[i].getVectorIndex(j), 0, MLKEMEngine.N, buf, buflen);
                while (ctr < MLKEMEngine.N)
                {
                    int off = buflen % 3;
                    for (int k = 0; k < off; k++)
                    {
                        buf[k] = buf[buflen - off + k];
                    }

                    xof.doOutput(buf, off, SHAKE128_RATE * 2);

                    buflen = off + SHAKE128_RATE;
                    // Error in code Section Unsure
                    ctr += rejectionSampling(aMatrix[i].getVectorIndex(j), ctr, MLKEMEngine.N - ctr, buf, buflen);
                }
            }
        }
    }

    private static int rejectionSampling(Poly outputBuffer, int coeffOff, int len, byte[] inpBuf, int inpBufLen)
    {
        short Q = (short)MLKEMEngine.Q;

        int ctr = 0, pos = 0;
        while (ctr < len && pos + 3 <= inpBufLen)
        {
            short d1 = (short)(((((short)(inpBuf[pos + 0] & 0xFF)) >> 0) | (((short)(inpBuf[pos + 1] & 0xFF)) << 8)) & 0xFFF);
            short d2 = (short)(((((short)(inpBuf[pos + 1] & 0xFF)) >> 4) | (((short)(inpBuf[pos + 2] & 0xFF)) << 4)) & 0xFFF);
            pos += 3;

            if (d1 < Q)
            {
                outputBuffer.setCoeffIndex(coeffOff + ctr, (short)d1);
                ctr++;
            }
            if (ctr < len && d2 < Q)
            {
                outputBuffer.setCoeffIndex(coeffOff + ctr, (short)d2);
                ctr++;
            }
        }
        return ctr;
    }
}
