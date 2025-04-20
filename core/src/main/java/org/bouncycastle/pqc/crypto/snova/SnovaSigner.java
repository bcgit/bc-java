package org.bouncycastle.pqc.crypto.snova;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.GF16;

public class SnovaSigner
    implements MessageSigner
{
    private SnovaParameters params;
    private SnovaEngine engine;
    private SecureRandom random;
    private final SHAKEDigest shake = new SHAKEDigest(256);
    private SnovaPublicKeyParameters pubKey;
    private SnovaPrivateKeyParameters privKey;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (SnovaPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (SnovaPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (SnovaPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
        engine = new SnovaEngine(params);
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] hash = getMessageHash(message);
        byte[] salt = new byte[params.getSaltLength()];
        random.nextBytes(salt);
        byte[] signature = new byte[((params.getN() * params.getLsq() + 1) >>> 1) + params.getSaltLength()];
        SnovaKeyElements keyElements = new SnovaKeyElements(params);
        byte[] publicKeySeed;
        byte[] ptPrivateKeySeed;
        if (params.isSkIsSeed())
        {
            byte[] seedPair = privKey.getPrivateKey();
            publicKeySeed = Arrays.copyOfRange(seedPair, 0, SnovaKeyPairGenerator.publicSeedLength);
            ptPrivateKeySeed = Arrays.copyOfRange(seedPair, SnovaKeyPairGenerator.publicSeedLength, seedPair.length);
            engine.genMap1T12Map2(keyElements, publicKeySeed, ptPrivateKeySeed);
        }
        else
        {
            byte[] privateKey = privKey.getPrivateKey();
            byte[] tmp = new byte[(privateKey.length - SnovaKeyPairGenerator.publicSeedLength - SnovaKeyPairGenerator.privateSeedLength) << 1];
            GF16Utils.decodeMergeInHalf(privateKey, tmp, tmp.length);
            int inOff = 0;
            inOff = SnovaKeyElements.copy3d(tmp, inOff, keyElements.map1.aAlpha);
            inOff = SnovaKeyElements.copy3d(tmp, inOff, keyElements.map1.bAlpha);
            inOff = SnovaKeyElements.copy3d(tmp, inOff, keyElements.map1.qAlpha1);
            inOff = SnovaKeyElements.copy3d(tmp, inOff, keyElements.map1.qAlpha2);
            inOff = SnovaKeyElements.copy3d(tmp, inOff, keyElements.T12);
            inOff = SnovaKeyElements.copy4d(tmp, inOff, keyElements.map2.f11);
            inOff = SnovaKeyElements.copy4d(tmp, inOff, keyElements.map2.f12);
            SnovaKeyElements.copy4d(tmp, inOff, keyElements.map2.f21);
            publicKeySeed = Arrays.copyOfRange(privateKey, privateKey.length - SnovaKeyPairGenerator.publicSeedLength - SnovaKeyPairGenerator.privateSeedLength, privateKey.length - SnovaKeyPairGenerator.privateSeedLength);
            ptPrivateKeySeed = Arrays.copyOfRange(privateKey, privateKey.length - SnovaKeyPairGenerator.privateSeedLength, privateKey.length);
        }
        signDigestCore(signature, hash, salt, keyElements.map1.aAlpha, keyElements.map1.bAlpha, keyElements.map1.qAlpha1, keyElements.map1.qAlpha2,
            keyElements.T12, keyElements.map2.f11, keyElements.map2.f12, keyElements.map2.f21, publicKeySeed, ptPrivateKeySeed);
        return Arrays.concatenate(signature, message);
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        byte[] hash = getMessageHash(message);
        MapGroup1 map1 = new MapGroup1(params);
        byte[] pk = pubKey.getEncoded();
        byte[] publicKeySeed = Arrays.copyOf(pk, SnovaKeyPairGenerator.publicSeedLength);
        byte[] p22_source = Arrays.copyOfRange(pk, SnovaKeyPairGenerator.publicSeedLength, pk.length);
        engine.genABQP(map1, publicKeySeed);
        byte[][][][] p22 = new byte[params.getM()][params.getO()][params.getO()][params.getLsq()];
        if ((params.getLsq() & 1) == 0)
        {
            MapGroup1.decodeP(p22_source, 0, p22, p22_source.length << 1);
        }
        else
        {
            byte[] p22_gf16s = new byte[p22_source.length << 1];
            GF16.decode(p22_source, p22_gf16s, p22_gf16s.length);
            MapGroup1.fillP(p22_gf16s, 0, p22, p22_gf16s.length);
        }

        return verifySignatureCore(hash, signature, publicKeySeed, map1, p22);
    }

    void createSignedHash(
        byte[] ptPublicKeySeed, int seedLengthPublic,
        byte[] digest, int bytesDigest,
        byte[] arraySalt, int saltOff, int bytesSalt,
        byte[] signedHashOut, int bytesHash)
    {
        // 1. Absorb public key seed
        shake.update(ptPublicKeySeed, 0, seedLengthPublic);

        // 2. Absorb message digest
        shake.update(digest, 0, bytesDigest);

        // 3. Absorb salt
        shake.update(arraySalt, saltOff, bytesSalt);

        // 4. Finalize absorption and squeeze output
        shake.doFinal(signedHashOut, 0, bytesHash);
    }

    void signDigestCore(byte[] ptSignature, byte[] digest, byte[] arraySalt,
                        byte[][][] Aalpha, byte[][][] Balpha,
                        byte[][][] Qalpha1, byte[][][] Qalpha2,
                        byte[][][] T12, byte[][][][] F11,
                        byte[][][][] F12, byte[][][][] F21,
                        byte[] ptPublicKeySeed, byte[] ptPrivateKeySeed)
    {
        // Initialize constants from parameters
        final int m = params.getM();
        final int l = params.getL();
        final int lsq = params.getLsq();
        final int alpha = params.getAlpha();
        final int v = params.getV();
        final int o = params.getO();
        final int n = params.getN();
        final int mxlsq = m * lsq;
        final int oxlsq = o * lsq;
        final int vxlsq = v * lsq;
        final int bytesHash = (oxlsq + 1) >>> 1;
        final int bytesSalt = 16;

        // Initialize matrices and arrays
        byte[][] Gauss = new byte[mxlsq][mxlsq + 1];
        byte[][] Temp = new byte[lsq][lsq];
        byte[] solution = new byte[mxlsq];

        byte[][][] Left = new byte[alpha][v][lsq];
        byte[][][] Right = new byte[alpha][v][lsq];
        byte[] leftXTmp = new byte[lsq];
        byte[] rightXtmp = new byte[lsq];
        byte[] FvvGF16Matrix = new byte[lsq];
        byte[] hashInGF16 = new byte[mxlsq];
        byte[] vinegarGf16 = new byte[n * lsq];
        byte[] signedHash = new byte[bytesHash];
        byte[] vinegarBytes = new byte[(vxlsq + 1) >>> 1];

        // Temporary matrices
        byte[] gf16mTemp0 = new byte[l];

        int flagRedo;
        byte numSign = 0;
        byte valLeft, valB, valA, valRight;
        // Step 1: Create signed hash
        createSignedHash(ptPublicKeySeed, ptPublicKeySeed.length, digest, digest.length,
            arraySalt, 0, arraySalt.length, signedHash, bytesHash);
        GF16.decode(signedHash, 0, hashInGF16, 0, hashInGF16.length);

        do
        {
            // Initialize Gauss matrix
            for (int i = 0; i < Gauss.length; ++i)
            {
                Arrays.fill(Gauss[i], (byte)0);
            }
            numSign++;

            // Fill last column of Gauss matrix
            for (int i = 0; i < mxlsq; i++)
            {
                Gauss[i][mxlsq] = hashInGF16[i];
            }

            // Generate vinegar values
            shake.update(ptPrivateKeySeed, 0, ptPrivateKeySeed.length);
            shake.update(digest, 0, digest.length);
            shake.update(arraySalt, 0, arraySalt.length);
            shake.update(numSign);
            shake.doFinal(vinegarBytes, 0, vinegarBytes.length);

            GF16.decode(vinegarBytes, vinegarGf16, vinegarBytes.length << 1);

            for (int i = 0, ixlsq = 0; i < m; i++, ixlsq += lsq)
            {
                Arrays.fill(FvvGF16Matrix, (byte)0);
                // Evaluate vinegar part of central map
                for (int a = 0, miPrime = i; a < alpha; a++, miPrime++)
                {
                    if (miPrime >= o)
                    {
                        miPrime -= o;
                    }
                    for (int j = 0, jxlsq = 0; j < v; j++, jxlsq += lsq)
                    {
                        GF16Utils.gf16mTranMulMul(vinegarGf16, jxlsq, Aalpha[i][a], Balpha[i][a], Qalpha1[i][a],
                            Qalpha2[i][a], gf16mTemp0, Left[a][j], Right[a][j], l);
                    }

                    for (int j = 0; j < v; j++)
                    {
                        // Gaussian elimination setup
                        for (int k = 0; k < v; k++)
                        {
                            GF16Utils.gf16mMulMulTo(Left[a][j], F11[miPrime][j][k], Right[a][k], gf16mTemp0, FvvGF16Matrix, l);
                        }
                    }
                }

                for (int j = 0, off = 0; j < l; j++)
                {
                    for (int k = 0; k < l; k++)
                    {
                        Gauss[ixlsq + off][mxlsq] ^= FvvGF16Matrix[off++];
                    }
                }
//            }
//            // TODO: think about why this two loops can merge together?
//            // Compute the coefficients of Xo and put into Gauss matrix and compute the coefficients of Xo^t and add into Gauss matrix
//            for (int i = 0, ixlsq = 0; i < m; ++i, ixlsq += lsq)
//            {
                for (int index = 0, idxlsq = 0; index < o; ++index, idxlsq += lsq)
                {
                    for (int a = 0, mi_prime = i; a < alpha; ++a, ++mi_prime)
                    {
                        if (mi_prime >= o)
                        {
                            mi_prime -= o;
                        }
                        // Initialize Temp to zero
                        for (int ti = 0; ti < lsq; ++ti)
                        {
                            Arrays.fill(Temp[ti], (byte)0);
                        }
                        // Process each j for Left part
                        for (int j = 0; j < v; ++j)
                        {
                            GF16Utils.gf16mMulMul(Left[a][j], F12[mi_prime][j][index], Qalpha2[i][a], gf16mTemp0, leftXTmp, l);
                            GF16Utils.gf16mMulMul(Qalpha1[i][a], F21[mi_prime][index][j], Right[a][j], gf16mTemp0, rightXtmp, l);
                            // Accumulate into Temp from leftXTmp and Balpha[mi][a]
                            // rlra_l is short for "rowLeft_rowA times l"
                            for (int ti = 0, colB_colRight = 0, rlraxl = 0; ti < lsq; ++ti, ++colB_colRight)
                            {
                                if (colB_colRight == l)
                                {
                                    colB_colRight = 0;
                                    rlraxl += l;
                                }
                                valLeft = leftXTmp[rlraxl];
                                valRight = rightXtmp[colB_colRight];
                                // clrrxl is short for "rowLeft_rowA times l"
                                // rbcaxl is short for "rowB_colA times l"
                                for (int tj = 0, rowB_colA = 0, colLeft_rowRight = 0, clrrxl = 0, rbcaxl = 0; tj < lsq;
                                     ++tj, ++rowB_colA, rbcaxl += l)
                                {
                                    if (rowB_colA == l)
                                    {
                                        rowB_colA = 0;
                                        rbcaxl = 0;
                                        colLeft_rowRight++;
                                        clrrxl += l;
                                        valLeft = leftXTmp[rlraxl + colLeft_rowRight];
                                        valRight = rightXtmp[clrrxl + colB_colRight];
                                    }
                                    valB = Balpha[i][a][rbcaxl + colB_colRight];
                                    valA = Aalpha[i][a][rlraxl + rowB_colA];
                                    Temp[ti][tj] ^= GF16.mul(valLeft, valB) ^ GF16.mul(valA, valRight);
                                }
                            }
                        }
                        // Add Temp to Gauss matrix
                        for (int ti = 0; ti < lsq; ++ti)
                        {
                            for (int tj = 0; tj < lsq; ++tj)
                            {
                                Gauss[ixlsq + ti][idxlsq + tj] ^= Temp[ti][tj];
                            }
                        }
                    }
                }
            }
            // Gaussian elimination implementation
            flagRedo = performGaussianElimination(Gauss, solution, mxlsq);
        }
        while (flagRedo != 0);

        // Copy vinegar variables
        for (int idx = 0, idxlsq = 0; idx < v; idx++, idxlsq += lsq)
        {
            for (int i = 0, ixlsq = 0; i < o; i++, ixlsq += lsq)
            {
                GF16Utils.gf16mMulTo(T12[idx][i], solution, ixlsq, vinegarGf16, idxlsq, l);
            }
        }

        // Copy remaining oil variables
        System.arraycopy(solution, 0, vinegarGf16, vxlsq, oxlsq);
        GF16.encode(vinegarGf16, ptSignature, vinegarGf16.length);

        System.arraycopy(arraySalt, 0, ptSignature, ptSignature.length - bytesSalt, bytesSalt);
    }

    boolean verifySignatureCore(byte[] digest, byte[] signature, byte[] publicKeySeed, MapGroup1 map1, byte[][][][] p22)
    {
        final int lsq = params.getLsq();
        final int o = params.getO();
        final int oxlsq = o * lsq;
        final int bytesHash = (oxlsq + 1) >>> 1;
        final int bytesSalt = params.getSaltLength();
        final int m = params.getM();
        final int n = params.getN();
        final int nxlsq = n * lsq;

        int bytesSignature = ((nxlsq) + 1) >>> 1;

        // Step 1: Regenerate signed hash using public key seed, digest and salt
        byte[] signedHash = new byte[bytesHash];
        createSignedHash(publicKeySeed, publicKeySeed.length, digest, digest.length,
            signature, bytesSignature, bytesSalt, signedHash, bytesHash);

        // Handle odd-length adjustment (if needed)
        if (((oxlsq) & 1) != 0)
        {
            signedHash[bytesHash - 1] &= 0x0F;
        }

        // Step 2: Convert signature to GF16 matrices
        byte[] decodedSig = new byte[nxlsq];
        GF16.decode(signature, 0, decodedSig, 0, decodedSig.length);

        // Step 3: Evaluate signature using public key
        byte[] computedHashBytes = new byte[m * lsq];
        evaluation(computedHashBytes, map1, p22, decodedSig);//signatureGF16Matrix);

        // Convert computed hash matrix to bytes
        byte[] encodedHash = new byte[bytesHash];
        GF16.encode(computedHashBytes, encodedHash, computedHashBytes.length);

        // Step 4: Compare hashes
        return Arrays.areEqual(signedHash, encodedHash);
    }

    private void evaluation(byte[] hashMatrix, MapGroup1 map1, byte[][][][] p22, byte[] signature)
    {
        final int m = params.getM();
        final int alpha = params.getAlpha();
        final int n = params.getN();
        final int l = params.getL();
        final int lsq = params.getLsq();
        final int o = params.getO();

        byte[][][] Left = new byte[alpha][n][lsq];
        byte[][][] Right = new byte[alpha][n][lsq];
        byte[] temp = new byte[lsq];

        // Evaluate Left and Right matrices
        for (int mi = 0, mixlsq = 0; mi < m; mi++, mixlsq += lsq)
        {
            for (int si = 0, sixlsq = 0; si < n; si++, sixlsq += lsq)
            {
                for (int a = 0; a < alpha; a++)
                {
                    // Left[mi][a][si] = Aalpha * (sig^T * Qalpha1)
                    // Right[mi][a][si] = (Qalpha2 * sig) * Balpha
                    GF16Utils.gf16mTranMulMul(signature, sixlsq, map1.aAlpha[mi][a], map1.bAlpha[mi][a], map1.qAlpha1[mi][a],
                        map1.qAlpha2[mi][a], temp, Left[a][si], Right[a][si], l);
                }
            }

            // Process P matrices and accumulate results
            for (int a = 0, miPrime = mi; a < alpha; a++, miPrime++)
            {
                if (miPrime >= o)
                {
                    miPrime -= o;
                }
                for (int ni = 0; ni < n; ni++)
                {
                    // sum_t0 = sum(P[miPrime][ni][nj] * Right[mi][a][nj])
                    byte[] p = getPMatrix(map1, p22, miPrime, ni, 0);
                    GF16Utils.gf16mMul(p, Right[a][0], temp, l);
                    for (int nj = 1; nj < n; nj++)
                    {
                        p = getPMatrix(map1, p22, miPrime, ni, nj);
                        GF16Utils.gf16mMulTo(p, Right[a][nj], temp, l);
                    }

                    // hashMatrix += Left[mi][a][ni] * temp
                    GF16Utils.gf16mMulTo(Left[a][ni], temp, hashMatrix, mixlsq, l);
                }
            }
        }
    }

    private byte[] getPMatrix(MapGroup1 map1, byte[][][][] p22, int mi, int ni, int nj)
    {
        final int v = params.getV();
        if (ni < v)
        {
            if (nj < v)
            {
                return map1.p11[mi][ni][nj];
            }
            else
            {
                return map1.p12[mi][ni][nj - v];
            }
        }
        else
        {
            if (nj < v)
            {
                return map1.p21[mi][ni - v][nj];
            }
            else
            {
                return p22[mi][ni - v][nj - v];
            }
        }
    }

    private int performGaussianElimination(byte[][] Gauss, byte[] solution, int size)
    {
        final int cols = size + 1;

        for (int i = 0; i < size; i++)
        {
            // Find pivot
            int pivot = i;
            while (pivot < size && Gauss[pivot][i] == 0)
            {
                pivot++;
            }

            // Check for singularity
            if (pivot >= size)
            {
                return 1; // Flag for redo
            }

            // Swap rows if needed
            if (pivot != i)
            {
                byte[] tempRow = Gauss[i];
                Gauss[i] = Gauss[pivot];
                Gauss[pivot] = tempRow;
            }

            // Normalize pivot row
            byte invPivot = GF16.inv(Gauss[i][i]);
            for (int j = i; j < cols; j++)
            {
                Gauss[i][j] = GF16.mul(Gauss[i][j], invPivot);
            }

            // Eliminate below
            for (int j = i + 1; j < size; j++)
            {
                byte factor = Gauss[j][i];
                if (factor != 0)
                {
                    for (int k = i; k < cols; k++)
                    {
                        Gauss[j][k] ^= GF16.mul(Gauss[i][k], factor);
                    }
                }
            }
        }

        // Back substitution
        for (int i = size - 1; i >= 0; i--)
        {
            byte tmp = Gauss[i][size];
            for (int j = i + 1; j < size; j++)
            {
                tmp ^= GF16.mul(Gauss[i][j], solution[j]);
            }
            solution[i] = tmp;
        }
        return 0;
    }

    private byte[] getMessageHash(byte[] message)
    {
        byte[] hash = new byte[shake.getDigestSize()];
        shake.update(message, 0, message.length);
        shake.doFinal(hash, 0);
        return hash;
    }
}
