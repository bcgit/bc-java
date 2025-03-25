package org.bouncycastle.pqc.crypto.snova;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

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
        if (params.isSkIsSeed())
        {

        }
        else
        {
            SnovaKeyElements esk = new SnovaKeyElements(params, engine);
            esk.skUnpack(privKey.getPrivateKey());
            signDigestCore(signature, hash, salt, esk.map1.aAlpha, esk.map1.bAlpha, esk.map1.qAlpha1, esk.map1.qAlpha2,
                esk.T12, esk.map2.f11, esk.map2.f12, esk.map2.f21, esk.publicKey.publicKeySeed, esk.ptPrivateKeySeed);
        }
        return new byte[0];
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return false;
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
            Arrays.stream(FvvGF16Matrix).forEach(row -> Arrays.fill(row, (byte)0));
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

            // Gaussian elimination setup
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < params.getL(); j++)
                {
                    for (int k = 0; k < params.getL(); k++)
                    {
                        int idx1 = i * lsq + j * params.getL() + k;
                        Gauss[idx1][m * lsq] = GF16Utils.add(
                            Gauss[idx1][m * lsq],
                            engine.getGF16m(FvvGF16Matrix[i], j, k)
                        );
                    }
                }
            }

            // Gaussian elimination implementation
            flagRedo = performGaussianElimination(Gauss, solution, m * lsq);

        }
        while (flagRedo != 0);

        // Build final signature
        //buildSignature(XInGF16Matrix, signatureGF16Matrix, T12, v, o, lsq);
        //void buildSignature(byte[][][] XIn, byte[][] signature,
        //                                byte[][][][] T12, int v, int o, int lsq)
        // Copy vinegar variables
        for (int idx = 0; idx < v; idx++)
        {
            System.arraycopy(XInGF16Matrix[idx], 0, signatureGF16Matrix[idx], 0, lsq);
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
            System.arraycopy(XInGF16Matrix[v + idx], 0, signatureGF16Matrix[v + idx], 0, lsq);
        }

        // Convert to packed bytes
        int bytePos = 0;
        for (int matIdx = 0; matIdx < signatureGF16Matrix.length; matIdx++)
        {
            for (int i = 0; i < l; i++)
            {
                for (int j = 0; j < l; j++)
                {
                    int nibblePos = bytePos % 2;
                    if (nibblePos == 0)
                    {
                        ptSignature[bytePos / 2] = (byte)(engine.getGF16m(signatureGF16Matrix[matIdx], i, j) << 4);
                    }
                    else
                    {
                        ptSignature[bytePos / 2] |= engine.getGF16m(signatureGF16Matrix[matIdx], i, j) & 0x0F;
                    }
                    bytePos++;
                }
            }
        }
        byte[] tmp = new byte[n * lsq];
        for (int i = 0; i < signatureGF16Matrix.length; ++i)
        {
            System.arraycopy(signatureGF16Matrix[i], 0, tmp, 0, signatureGF16Matrix[i].length);
        }
        GF16Utils.encode(tmp, ptSignature, 0, tmp.length);
        System.arraycopy(arraySalt, 0, ptSignature, 0, bytesSalt);

        // Clear sensitive data
        Arrays.fill(gf16mSecretTemp0, (byte)0);
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

    private int iPrime(int mi, int alpha)
    {
        // Implement index calculation based on SNOVA specification
        return (mi + alpha) % params.getM();
    }

}
