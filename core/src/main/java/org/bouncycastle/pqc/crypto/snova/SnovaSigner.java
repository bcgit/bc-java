package org.bouncycastle.pqc.crypto.snova;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

public class SnovaSigner
    implements MessageSigner
{
    private SnovaParameters params;
    private SnovaEngine engine;
    private SecureRandom random;
    private final SHAKEDigest digest = new SHAKEDigest(256);

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
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(message, 0, message.length);
        digest.doFinal(hash, 0);
        byte[] salt = new byte[params.getSaltLength()];
        random.nextBytes(salt);
        byte[] signature = new byte[((params.getN() * params.getLsq() + 1) >>> 1) + params.getSaltLength()];
        SnovaKeyElements keyElements = new SnovaKeyElements(params, engine);
        if (params.isSkIsSeed())
        {
            byte[] seedPair = privKey.getPrivateKey();
            keyElements.publicKey.publicKeySeed = Arrays.copyOfRange(seedPair, 0, SnovaKeyPairGenerator.publicSeedLength);
            keyElements.ptPrivateKeySeed = Arrays.copyOfRange(seedPair, SnovaKeyPairGenerator.publicSeedLength, seedPair.length);
            engine.genSeedsAndT12(keyElements.T12, keyElements.ptPrivateKeySeed);

            // Generate map components
            engine.genABQP(keyElements.map1, keyElements.publicKey.publicKeySeed, keyElements.fixedAbq);

            // Generate F matrices
            engine.genF(keyElements.map2, keyElements.map1, keyElements.T12);
        }
        else
        {
            keyElements.skUnpack(privKey.getPrivateKey());
        }
        signDigestCore(signature, hash, salt, keyElements.map1.aAlpha, keyElements.map1.bAlpha, keyElements.map1.qAlpha1, keyElements.map1.qAlpha2,
            keyElements.T12, keyElements.map2.f11, keyElements.map2.f12, keyElements.map2.f21, keyElements.publicKey.publicKeySeed, keyElements.ptPrivateKeySeed);
        return Arrays.concatenate(signature, message);
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(message, 0, message.length);
        digest.doFinal(hash, 0);
        SnovaKeyElements keyElements = new SnovaKeyElements(params, engine);
        byte[] pk = pubKey.getEncoded();
        System.arraycopy(pk, 0, keyElements.publicKey.publicKeySeed, 0, SnovaKeyPairGenerator.publicSeedLength);
        System.arraycopy(pk, SnovaKeyPairGenerator.publicSeedLength, keyElements.publicKey.P22, 0, keyElements.publicKey.P22.length);
        engine.genABQP(keyElements.map1, keyElements.publicKey.publicKeySeed, keyElements.fixedAbq);
        byte[] p22_gf16s = new byte[keyElements.publicKey.P22.length << 1];
        GF16Utils.decode(keyElements.publicKey.P22, p22_gf16s, p22_gf16s.length);
        byte[][][][] p22 = new byte[params.getM()][params.getO()][params.getO()][params.getLsq()];
        MapGroup1.fillP(p22_gf16s, 0, p22, p22_gf16s.length);
        return verifySignatureCore(hash, signature, keyElements.publicKey, keyElements.map1, p22);
    }

    public static void createSignedHash(
        byte[] digest, int bytesDigest,
        byte[] ptPublicKeySeed, int seedLengthPublic,
        byte[] arraySalt, int bytesSalt,
        byte[] signedHashOut, int bytesHash
    )
    {
        // Initialize SHAKE256 XOF
        SHAKEDigest shake = new SHAKEDigest(256);

        // 1. Absorb public key seed
        shake.update(ptPublicKeySeed, 0, seedLengthPublic);

        // 2. Absorb message digest
        shake.update(digest, 0, bytesDigest);

        // 3. Absorb salt
        shake.update(arraySalt, 0, bytesSalt);

        // 4. Finalize absorption and squeeze output
        shake.doFinal(signedHashOut, 0, bytesHash);
    }

    public void signDigestCore(byte[] ptSignature, byte[] digest, byte[] arraySalt,
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
        final int bytesHash = (o * lsq + 1) >>> 1;
        final int bytesSalt = 16;

        // Initialize matrices and arrays
        byte[][] Gauss = new byte[m * lsq][m * lsq + 1];
        byte[][] Temp = new byte[lsq][lsq];
        byte[] solution = new byte[m * lsq];

        byte[][][][][] Left = new byte[m][alpha][v][l][l];
        byte[][][][][] Right = new byte[m][alpha][v][l][l];
        byte[][] leftXTmp = new byte[l][l];
        byte[][] rightXtmp = new byte[l][l];
        byte[][][] XInGF16Matrix = new byte[n][l][l];
        byte[][] FvvGF16Matrix = new byte[m][lsq];
        byte[] hashInGF16 = new byte[m * lsq];
        byte[][] signatureGF16Matrix = new byte[n][lsq];

        byte[] signedHash = new byte[bytesHash];
        byte[] vinegarBytes = new byte[(v * lsq + 1) / 2];

        // Temporary matrices
        byte[][] gf16mTemp0 = new byte[l][l];
        byte[][] gf16mTemp1 = new byte[l][l];
        byte[] gf16mSecretTemp0 = new byte[lsq];

        int flagRedo;
        byte numSign = 0;

        // Step 1: Create signed hash
        createSignedHash(digest, digest.length, ptPublicKeySeed, ptPublicKeySeed.length,
            arraySalt, arraySalt.length, signedHash, bytesHash);
        GF16Utils.decode(signedHash, 0, hashInGF16, 0, hashInGF16.length);

        do
        {
            // Initialize Gauss matrix
            for (int i = 0; i < Gauss.length; ++i)
            {
                Arrays.fill(Gauss[i], (byte)0);
            }
            numSign++;
            //flagRedo = 0;

            // Fill last column of Gauss matrix
            for (int i = 0; i < m * lsq; i++)
            {
                Gauss[i][m * lsq] = hashInGF16[i];
            }

            // Generate vinegar values
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(ptPrivateKeySeed, 0, ptPrivateKeySeed.length);
            shake.update(digest, 0, digest.length);
            shake.update(arraySalt, 0, arraySalt.length);
            shake.update(numSign);
            shake.doFinal(vinegarBytes, 0, vinegarBytes.length);
            byte[] tmp = new byte[vinegarBytes.length << 1];
            GF16Utils.decode(vinegarBytes, tmp, tmp.length);
            MapGroup1.fillAlpha(tmp, 0, XInGF16Matrix, tmp.length);

            // Evaluate vinegar part of central map
            for (int mi = 0; mi < m; mi++)
            {
                for (int a = 0; a < alpha; a++)
                {
                    for (int idx = 0; idx < v; idx++)
                    {
                        transposeGF16Matrix(XInGF16Matrix[idx], gf16mTemp0);
                        multiplyGF16Matrices(gf16mTemp0, Qalpha1[mi][a], gf16mTemp1);
                        multiplyGF16Matrices(Aalpha[mi][a], gf16mTemp1, Left[mi][a][idx]);

                        multiplyGF16Matrices(Qalpha2[mi][a], XInGF16Matrix[idx], gf16mTemp1);
                        multiplyGF16Matrices(gf16mTemp1, Balpha[mi][a], Right[mi][a][idx]);
                    }
                }
            }

            // Matrix operations for Fvv
            for (int i = 0; i < FvvGF16Matrix.length; ++i)
            {
                Arrays.fill(FvvGF16Matrix[i], (byte)0);
            }
            for (int mi = 0; mi < m; mi++)
            {
                for (int a = 0; a < alpha; a++)
                {
                    int miPrime = iPrime(mi, a);
                    for (int j = 0; j < v; j++)
                    {
                        for (int k = 0; k < v; k++)
                        {
                            multiplyGF16Matrices(Left[mi][a][j], F11[miPrime][j][k], gf16mTemp0);
                            multiplyGF16Matrices(gf16mTemp0, Right[mi][a][k], gf16mTemp1);
                            addGF16Matrices(FvvGF16Matrix[mi], gf16mTemp1, FvvGF16Matrix[mi]);
                        }
                    }
                }
            }

            int idx2 = m * lsq;
            // Gaussian elimination setup
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < l; j++)
                {
                    for (int k = 0; k < l; k++)
                    {
                        int idx1 = i * lsq + j * l + k;
                        Gauss[idx1][idx2] ^= engine.getGF16m(FvvGF16Matrix[i], j, k);
                    }
                }
            }

            // Compute the coefficients of Xo and put into Gauss matrix and compute the coefficients of Xo^t and add into Gauss matrix
            for (int mi = 0; mi < m; ++mi)
            {
                for (int index = 0; index < o; ++index)
                {
                    for (int a = 0; a < alpha; ++a)
                    {
                        int mi_prime = iPrime(mi, a);
                        // Initialize Temp to zero
                        for (int ti = 0; ti < lsq; ++ti)
                        {
                            Arrays.fill(Temp[ti], (byte)0);
                        }
                        // Process each j for Left part
                        for (int j = 0; j < v; ++j)
                        {
                            multiplyGF16Matrices(Left[mi][a][j], F12[mi_prime][j][index], gf16mTemp0);
                            multiplyGF16Matrices(gf16mTemp0, Qalpha2[mi][a], leftXTmp);
                            // Accumulate into Temp from leftXTmp and Balpha[mi][a]
                            for (int ti = 0; ti < lsq; ++ti)
                            {
                                for (int tj = 0; tj < lsq; ++tj)
                                {
                                    int rowLeft = ti / l;
                                    int colLeft = tj / l;
                                    byte valLeft = leftXTmp[rowLeft][colLeft];
                                    int rowB = tj % l;
                                    int colB = ti % l;
                                    byte valB = engine.getGF16m(Balpha[mi][a], rowB, colB);
                                    byte product = GF16Utils.mul(valLeft, valB);
                                    Temp[ti][tj] ^= product;
                                }
                            }
                        }
                        // Process each j for Right part
                        for (int j = 0; j < v; ++j)
                        {
                            multiplyGF16Matrices(Qalpha1[mi][a], F21[mi_prime][index][j], gf16mTemp0);
                            multiplyGF16Matrices(gf16mTemp0, Right[mi][a][j], rightXtmp);
                            // Accumulate into Temp from Aalpha[mi][a] and rightXtmp
                            for (int ti = 0; ti < lsq; ++ti)
                            {
                                for (int tj = 0; tj < lsq; ++tj)
                                {
                                    int rowA = ti / l;
                                    int colA = tj % l;
                                    byte valA = engine.getGF16m(Aalpha[mi][a], rowA, colA);
                                    int rowRight = tj / l;
                                    int colRight = ti % l;
                                    byte valRight = rightXtmp[rowRight][colRight];
                                    byte product = GF16Utils.mul(valA, valRight);
                                    Temp[ti][tj] = GF16Utils.add(Temp[ti][tj], product);
                                }
                            }
                        }
                        // Add Temp to Gauss matrix
                        for (int ti = 0; ti < lsq; ++ti)
                        {
                            for (int tj = 0; tj < lsq; ++tj)
                            {
                                int gaussRow = mi * lsq + ti;
                                int gaussCol = index * lsq + tj;
                                Gauss[gaussRow][gaussCol] = GF16Utils.add(Gauss[gaussRow][gaussCol], Temp[ti][tj]);
                            }
                        }
                    }
                }
            }


            // Gaussian elimination implementation
            flagRedo = performGaussianElimination(Gauss, solution, m * lsq);

        }
        while (flagRedo != 0);

        for (int index = 0; index < o; ++index)
        {
            for (int i = 0; i < l; ++i)
            {
                for (int j = 0; j < l; ++j)
                {
                    XInGF16Matrix[index + v][i][j] = solution[index * lsq + i * l + j];
                }
            }
        }
        // Copy vinegar variables
        for (int idx = 0; idx < v; idx++)
        {
            for (int i = 0; i < l; ++i)
            {
                System.arraycopy(XInGF16Matrix[idx][i], 0, signatureGF16Matrix[idx], i * l, l);
            }
        }

        // Process oil variables with T12 matrix
        for (int idx = 0; idx < v; idx++)
        {
            for (int i = 0; i < o; i++)
            {
                multiplyGF16Matrices(T12[idx][i], XInGF16Matrix[v + i], gf16mTemp0);
                addGF16Matrices(signatureGF16Matrix[idx], gf16mTemp0, signatureGF16Matrix[idx]);
            }
        }

        // Copy remaining oil variables
        for (int idx = 0; idx < o; idx++)
        {
            for (int i = 0; i < l; ++i)
            {
                System.arraycopy(XInGF16Matrix[v + idx][i], 0, signatureGF16Matrix[v + idx], i * l, l);
            }
        }
        byte[] tmp = new byte[n * lsq];
        for (int idx = 0; idx < signatureGF16Matrix.length; ++idx)
        {
            System.arraycopy(signatureGF16Matrix[idx], 0, tmp, idx * lsq, lsq);
        }
        GF16Utils.encode(tmp, ptSignature, 0, tmp.length);

        System.arraycopy(arraySalt, 0, ptSignature, ptSignature.length - bytesSalt, bytesSalt);

        // Clear sensitive data
        Arrays.fill(gf16mSecretTemp0, (byte)0);
    }

    public boolean verifySignatureCore(byte[] digest, byte[] signature, PublicKey pkx, MapGroup1 map1, byte[][][][] p22)
    {
        final int bytesHash = (params.getO() * params.getLsq() + 1) >>> 1;
        final int bytesSalt = params.getSaltLength();
        final int l = params.getL();
        final int lsq = params.getLsq();
        final int m = params.getM();
        final int n = params.getN();
        final int v = params.getV();
        final int o = params.getO();
        int bytesSignature = ((n * lsq) + 1) >>> 1;

        // Extract salt from signature
        byte[] ptSalt = Arrays.copyOfRange(signature, bytesSignature, bytesSignature + bytesSalt);
        //byte[] signatureBody = Arrays.copyOf(signature, signature.length - bytesSalt);

        // Step 1: Regenerate signed hash using public key seed, digest and salt
        byte[] signedHash = new byte[bytesHash];
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(pkx.publicKeySeed, 0, pkx.publicKeySeed.length);
        shake.update(digest, 0, digest.length);
        shake.update(ptSalt, 0, ptSalt.length);
        shake.doFinal(signedHash, 0, bytesHash);

        // Handle odd-length adjustment (if needed)
        if ((o * lsq) % 2 != 0)
        {
            signedHash[bytesHash - 1] &= 0x0F;
        }

        // Step 2: Convert signature to GF16 matrices
        byte[][][] signatureGF16Matrix = new byte[n][l][l];
        byte[] decodedSig = new byte[n * lsq];
        GF16Utils.decode(signature, 0, decodedSig, 0, decodedSig.length);

        for (int i = 0; i < n; i++)
        {
            for (int row = 0; row < l; row++)
            {
                System.arraycopy(decodedSig, i * lsq + row * l,
                    signatureGF16Matrix[i][row], 0, l);
            }
        }

        // Step 3: Evaluate signature using public key
        byte[][][] computedHashMatrix = new byte[m][l][l];
        evaluation(computedHashMatrix, map1, p22, signatureGF16Matrix);

        // Convert computed hash matrix to bytes
        byte[] computedHashBytes = new byte[m * lsq];
        for (int i = 0; i < m; i++)
        {
            for (int row = 0; row < l; row++)
            {
                System.arraycopy(computedHashMatrix[i][row], 0,
                    computedHashBytes, i * lsq + row * l, l);
            }
        }
        byte[] encodedHash = new byte[bytesHash];
        GF16Utils.encode(computedHashBytes, encodedHash, 0, computedHashBytes.length);

        // Step 4: Compare hashes
        return Arrays.areEqual(signedHash, encodedHash);
    }

    private void evaluation(byte[][][] hashMatrix, MapGroup1 map1, byte[][][][] p22, byte[][][] signature)
    {
        final int m = params.getM();
        final int alpha = params.getAlpha();
        final int n = params.getN();
        final int v = params.getV();
        final int l = params.getL();

        byte[][][][][] Left = new byte[m][alpha][n][l][l];
        byte[][][][][] Right = new byte[m][alpha][n][l][l];
        byte[][] temp = new byte[l][l];
        byte[][] transposedSig = new byte[l][l];

        // Evaluate Left and Right matrices
        for (int mi = 0; mi < m; mi++)
        {
            for (int si = 0; si < n; si++)
            {
                transposeGF16Matrix(signature[si], transposedSig);
                for (int a = 0; a < alpha; a++)
                {
                    // Left[mi][a][si] = Aalpha * (sig^T * Qalpha1)
                    multiplyGF16Matrices(transposedSig, map1.qAlpha1[mi][a], temp);
                    multiplyGF16Matrices(map1.aAlpha[mi][a], temp, Left[mi][a][si]);

                    // Right[mi][a][si] = (Qalpha2 * sig) * Balpha
                    multiplyGF16Matrices(map1.qAlpha2[mi][a], signature[si], temp);
                    multiplyGF16Matrices(temp, map1.bAlpha[mi][a], Right[mi][a][si]);
                }
            }
        }

        // Initialize hash matrix to zero
        for (int mi = 0; mi < m; mi++)
        {
            for (int i = 0; i < l; i++)
            {
                Arrays.fill(hashMatrix[mi][i], (byte)0);
            }
        }

        // Process P matrices and accumulate results
        byte[][] sumTemp = new byte[l][l];
        byte[][] pTemp = new byte[l][l];
        for (int mi = 0; mi < m; mi++)
        {
            for (int a = 0; a < alpha; a++)
            {
                int miPrime = iPrime(mi, a);

                for (int ni = 0; ni < n; ni++)
                {
                    // sum_t0 = sum(P[miPrime][ni][nj] * Right[mi][a][nj])
                    for (int i = 0; i < l; i++)
                    {
                        Arrays.fill(sumTemp[i], (byte)0);
                    }

                    for (int nj = 0; nj < n; nj++)
                    {
                        byte[] p = getPMatrix(map1, p22, miPrime, ni, nj);
                        multiplyGF16Matrices(p, Right[mi][a][nj], pTemp);
                        addGF16Matrices(sumTemp, pTemp, sumTemp);
                    }

                    // hashMatrix += Left[mi][a][ni] * sumTemp
                    multiplyGF16Matrices(Left[mi][a][ni], sumTemp, temp);
                    addGF16Matrices(hashMatrix[mi], temp, hashMatrix[mi]);
                }
            }
        }
    }

    // Helper method to get appropriate P matrix based on indices
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

    private void transposeGF16Matrix(byte[][] src, byte[][] dest)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            for (int j = 0; j < params.getL(); j++)
            {
                dest[i][j] = src[j][i];
            }
        }
    }

    private void multiplyGF16Matrices(byte[][] a, byte[][] b, byte[][] result)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            Arrays.fill(result[i], (byte)0);
            for (int j = 0; j < params.getL(); j++)
            {
                byte sum = 0;
                for (int k = 0; k < params.getL(); k++)
                {
                    sum = GF16Utils.add(sum, GF16Utils.mul(
                        a[i][k],
                        b[k][j]
                    ));
                }
                result[i][j] = sum;
            }
        }
    }

    private void multiplyGF16Matrices(byte[][] a, byte[] b, byte[][] result)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            Arrays.fill(result[i], (byte)0);
            for (int j = 0; j < params.getL(); j++)
            {
                byte sum = 0;
                for (int k = 0; k < params.getL(); k++)
                {
                    sum = GF16Utils.add(sum, GF16Utils.mul(
                        a[i][k],
                        engine.getGF16m(b, k, j)
                    ));
                }
                result[i][j] = sum;
            }
        }
    }

    private void multiplyGF16Matrices(byte[] a, byte[][] b, byte[][] result)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            Arrays.fill(result[i], (byte)0);
            for (int j = 0; j < params.getL(); j++)
            {
                byte sum = 0;
                for (int k = 0; k < params.getL(); k++)
                {
                    sum = GF16Utils.add(sum, GF16Utils.mul(
                        engine.getGF16m(a, i, k),
                        b[k][j]
                    ));
                }
                result[i][j] = sum;
            }
        }
    }

    private void multiplyGF16Matrices(byte[] a, byte[] b, byte[][] result)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            Arrays.fill(result[i], (byte)0);
            for (int j = 0; j < params.getL(); j++)
            {
                byte sum = 0;
                for (int k = 0; k < params.getL(); k++)
                {
                    sum = GF16Utils.add(sum, GF16Utils.mul(
                        engine.getGF16m(a, i, k),
                        engine.getGF16m(b, k, j)
                    ));
                }
                result[i][j] = sum;
            }
        }
    }

    private int performGaussianElimination(byte[][] Gauss, byte[] solution, int size)
    {
        final int cols = size + 1;
        byte tGF16;

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
            byte invPivot = GF16Utils.inv(Gauss[i][i]);
            for (int j = i; j < cols; j++)
            {
                Gauss[i][j] = GF16Utils.mul(Gauss[i][j], invPivot);
            }

            // Eliminate below
            for (int j = i + 1; j < size; j++)
            {
                byte factor = Gauss[j][i];
                if (factor != 0)
                {
                    for (int k = i; k < cols; k++)
                    {
                        Gauss[j][k] = GF16Utils.add(Gauss[j][k], GF16Utils.mul(Gauss[i][k], factor));
                    }
                }
            }
        }

        // Back substitution
        for (int i = size - 1; i >= 0; i--)
        {
            solution[i] = Gauss[i][size];
            for (int j = i + 1; j < size; j++)
            {
                solution[i] = GF16Utils.add(solution[i], GF16Utils.mul(Gauss[i][j], solution[j]));
            }
        }

        return 0;
    }

    private void addGF16Matrices(byte[] a, byte[][] b, byte[] result)
    {
        for (int i = 0; i < b.length; i++)
        {
            for (int j = 0; j < b[i].length; ++j)
            {
                engine.setGF16m(result, i, j, GF16Utils.add(engine.getGF16m(a, i, j), b[i][j]));
            }
        }
    }

    private void addGF16Matrices(byte[][] a, byte[][] b, byte[][] result)
    {
        for (int i = 0; i < b.length; i++)
        {
            for (int j = 0; j < b[i].length; ++j)
            {
                result[i][j] = GF16Utils.add(a[i][j], b[i][j]);
            }
        }
    }

    private int iPrime(int mi, int alpha)
    {
        // Implement index calculation based on SNOVA specification
        return (mi + alpha) % params.getO();
    }

}
