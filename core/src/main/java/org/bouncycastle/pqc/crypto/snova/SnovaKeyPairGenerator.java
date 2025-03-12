package org.bouncycastle.pqc.crypto.snova;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class SnovaKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SnovaEngine engine;
    private static final int seedLength = 48;
    static final int publicSeedLength = 16;
    static final int privateSeedLength = 32;
    private SnovaParameters params;
    private SecureRandom random;
    private boolean initialized;

    @Override
    public void init(KeyGenerationParameters param)
    {
        SnovaKeyGenerationParameters snovaParams = (SnovaKeyGenerationParameters)param;
        this.params = snovaParams.getParameters();
        this.random = snovaParams.getRandom();
        this.initialized = true;
        this.engine = new SnovaEngine(params);
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        if (!initialized)
        {
            throw new IllegalStateException("SNOVA key pair generator not initialized");
        }

        // Generate seed pair according to SNOVA specifications
        byte[] seedPair = new byte[seedLength];
        random.nextBytes(seedPair);

        byte[] pk = new byte[publicSeedLength];
        byte[] sk = new byte[privateSeedLength];

        byte[] ptPublicKeySeed = Arrays.copyOfRange(seedPair, 0, publicSeedLength);
        byte[] ptPrivateKeySeed = Arrays.copyOfRange(seedPair, publicSeedLength, seedPair.length);

        if (params.isSkIsSeed())
        {
            generateKeysSSK(pk, sk, ptPublicKeySeed, ptPrivateKeySeed);
        }
        else
        {
            generateKeysESK(pk, sk, ptPublicKeySeed, ptPrivateKeySeed);
        }

        return new AsymmetricCipherKeyPair(
            new SnovaPublicKeyParameters(pk),
            new SnovaPrivateKeyParameters(sk)
        );
    }

    private void generateKeysSSK(byte[] pk, byte[] sk, byte[] ptPublicKeySeed, byte[] ptPrivateKeySeed)
    {
        // Implementation based on C's generate_keys_ssk
        System.arraycopy(ptPublicKeySeed, 0, sk, 0, ptPublicKeySeed.length);
        System.arraycopy(ptPrivateKeySeed, 0, sk, ptPublicKeySeed.length, ptPrivateKeySeed.length);

        // Actual key generation would go here using BC's SHAKE/AES implementations
        // This would include the matrix operations from the C code
        generatePublicKey(pk, ptPublicKeySeed, ptPrivateKeySeed);
    }

    private void generateKeysESK(byte[] pk, byte[] esk, byte[] ptPublicKeySeed, byte[] ptPrivateKeySeed)
    {
        // Implementation based on C's generate_keys_esk
        // Actual expanded key generation would go here
        generatePublicKey(pk, ptPublicKeySeed, ptPrivateKeySeed);
        packPrivateKey(esk, ptPublicKeySeed, ptPrivateKeySeed);
    }

    private void packPrivateKey(byte[] esk, byte[] ptPublicKeySeed, byte[] ptPrivateKeySeed)
    {
        SnovaKeyElements keyElements = new SnovaKeyElements(params);
        generateKeysCore(keyElements, ptPublicKeySeed, ptPrivateKeySeed);

        // Serialize all components
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        // Serialize map components
//        serializeMatrixGroup(bos, keyElements.map1.Aalpha);
//        serializeMatrixGroup(bos, keyElements.map1.Balpha);
//        serializeMatrixGroup(bos, keyElements.map1.Qalpha1);
//        serializeMatrixGroup(bos, keyElements.map1.Qalpha2);

        // Serialize T12
//        for (GF16Matrix[] row : keyElements.T12)
//        {
//            for (GF16Matrix matrix : row)
//            {
//                serializeMatrix(bos, matrix);
//            }
//        }

        // Add public and private seeds
        bos.write(ptPublicKeySeed, 0, ptPublicKeySeed.length);
        bos.write(ptPrivateKeySeed, 0, ptPrivateKeySeed.length);

        System.arraycopy(bos.toByteArray(), 0, esk, 0, esk.length);
    }

    private void serializeMatrixGroup(ByteArrayOutputStream bos, GF16Matrix[][][] group)
    {
        for (GF16Matrix[][] dim1 : group)
        {
            for (GF16Matrix[] dim2 : dim1)
            {
                for (GF16Matrix matrix : dim2)
                {
                    serializeMatrix(bos, matrix);
                }
            }
        }
    }

    private void serializeMatrix(ByteArrayOutputStream bos, GF16Matrix matrix)
    {
//        byte[] temp = new byte[(matrix.size * matrix.size + 1) / 2];
//        byte[] gf16s = new byte[matrix.size * matrix.size];
//
//        int idx = 0;
//        for (int i = 0; i < matrix.size; i++) {
//            for (int j = 0; j < matrix.size; j++) {
//                gf16s[idx++] = matrix.get(i, j);
//            }
//        }
//
//        GF16Utils.convertGF16sToBytes(temp, gf16s, gf16s.length);
//        bos.write(temp, 0, temp.length);
    }

    private void generatePublicKey(byte[] pk, byte[] ptPublicKeySeed, byte[] ptPrivateKeySeed)
    {

        // Generate key elements
        SnovaKeyElements keyElements = new SnovaKeyElements(params);
        generateKeysCore(keyElements, ptPublicKeySeed, ptPrivateKeySeed);

        // Pack public key components
        //packPublicKey(pk, keyElements);
    }

    private void generateKeysCore(SnovaKeyElements keyElements, byte[] pkSeed, byte[] skSeed)
    {
        // Generate T12 matrix
        genSeedsAndT12(keyElements.T12, skSeed);

        // Generate map components
        genABQP(keyElements.map1, pkSeed);
//
//        // Generate F matrices
//        genF(keyElements.map2, keyElements.map1, keyElements.T12);

        // Generate P22 matrix
//        genP22(keyElements.pk.P22, keyElements.T12, keyElements.map1.P21, keyElements.map2.F12);
    }

    private void genSeedsAndT12(byte[][][] T12, byte[] skSeed)
    {
        int bytesPrngPrivate = (params.getV() * params.getO() * params.getL() + 1) >>> 1;
        int gf16sPrngPrivate = params.getV() * params.getO() * params.getL();
        byte[] prngOutput = new byte[bytesPrngPrivate];

        // Generate PRNG output using SHAKE-256
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(skSeed, 0, skSeed.length);
        shake.doFinal(prngOutput, 0, prngOutput.length);

        // Convert bytes to GF16 array
        byte[] gf16PrngOutput = new byte[gf16sPrngPrivate];
        GF16Utils.decode(prngOutput, gf16PrngOutput, gf16sPrngPrivate);

        // Generate T12 matrices
        int ptArray = 0;
        int l = params.getL();
        for (int j = 0; j < params.getV(); j++)
        {
            for (int k = 0; k < params.getO(); k++)
            {
                //gen_a_FqS_ct
                engine.genAFqSCT(gf16PrngOutput, ptArray, T12[j][k]);
                ptArray += l;
            }
        }
    }

    private void genABQP(MapGroup1 map1, byte[] pkSeed)
    {
        int l = params.getL();
        int lsq = l * l;
        int m = params.getM();
        int alpha = params.getAlpha();
        int v = params.getV();
        int o = params.getO();
        int n = v + o;

        int gf16sPrngPublic = lsq * (2 * m * alpha + m * (n * n - m * m)) + l * 2 * m * alpha;
        byte[] qTemp = new byte[(m * alpha * 16 + m * alpha * 16) / l];
        byte[] prngOutput = new byte[(gf16sPrngPublic + 1) >> 1];

        if (params.isPkExpandShake())
        {
            // SHAKE-based expansion
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(pkSeed, 0, pkSeed.length);
            shake.doFinal(prngOutput, 0, prngOutput.length);
        }
        else
        {
            // Create a 16-byte IV (all zeros)
            byte[] iv = new byte[16]; // automatically zero-initialized
            // AES-CTR-based expansion
            // Set up AES engine in CTR (SIC) mode.
            BlockCipher aesEngine = AESEngine.newInstance();
            // SICBlockCipher implements CTR mode for AES.
            CTRModeCipher ctrCipher = SICBlockCipher.newInstance(aesEngine);
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(pkSeed), iv);
            ctrCipher.init(true, params);
            int blockSize = ctrCipher.getBlockSize(); // typically 16 bytes
            byte[] zeroBlock = new byte[blockSize];     // block of zeros
            byte[] blockOut = new byte[blockSize];

            int offset = 0;
            // Process full blocks
            while (offset + blockSize <= prngOutput.length)
            {
                ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
                System.arraycopy(blockOut, 0, prngOutput, offset, blockSize);
                offset += blockSize;
            }
            // Process any remaining partial block.
            if (offset < prngOutput.length)
            {
                ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
                int remaining = prngOutput.length - offset;
                System.arraycopy(blockOut, 0, prngOutput, offset, remaining);
            }
        }

        // Convert bytes to GF16 structures
        int inOff = map1.decode(prngOutput, (gf16sPrngPublic - qTemp.length) >> 1);
        GF16Utils.decode(prngOutput, inOff, qTemp, 0, qTemp.length);
//
        // Post-processing for invertible matrices
        for (int pi = 0; pi < m; ++pi)
        {
            for (int a = 0; a < alpha; ++a)
            {
                engine.makeInvertibleByAddingAS(map1.aAlpha[pi][a]);
            }
        }
        for (int pi = 0; pi < m; ++pi)
        {
            for (int a = 0; a < alpha; ++a)
            {
                engine.makeInvertibleByAddingAS(map1.bAlpha[pi][a]);
            }
        }

        int ptArray = 0;
        for (int pi = 0; pi < m; ++pi)
        {
            for (int a = 0; a < alpha; ++a)
            {
                engine.genAFqS(qTemp, ptArray, map1.qAlpha1[pi][a]);
                ptArray += l;
            }
        }
        for (int pi = 0; pi < m; ++pi)
        {
            for (int a = 0; a < alpha; ++a)
            {
                engine.genAFqS(qTemp, ptArray, map1.qAlpha2[pi][a]);
                ptArray += l;
            }
        }
    }


//    private void genF(MapGroup2 map2, MapGroup1 map1, GF16Matrix[][] T12)
//    {
//        // Matrix operations from C code's gen_F_ref
//        // Clone initial matrices
//        System.arraycopy(map1.P11, 0, map2.F11, 0, map1.P11.length);
//        System.arraycopy(map1.P12, 0, map2.F12, 0, map1.P12.length);
//        System.arraycopy(map1.P21, 0, map2.F21, 0, map1.P21.length);
//
//        // Perform matrix multiplications and additions
//        GF16Matrix temp = new GF16Matrix(params.getL());
//        for (int i = 0; i < params.getM(); i++) {
//            for (int j = 0; j < params.getV(); j++) {
//                for (int k = 0; k < params.getO(); k++) {
//                    for (int idx = 0; idx < params.getV(); idx++) {
//                        GF16Matrix.mul(map1.P11[i][j][idx], T12[idx][k], temp);
//                        GF16Matrix.add(map2.F12[i][j][k], temp, map2.F12[i][j][k]);
//                    }
//                }
//            }
//        }
//    }

    private void genP22(byte[] outP22, GF16Matrix[][] T12, GF16Matrix[][][] P21, GF16Matrix[][][] F12)
    {
//        GF16Matrix[][][] P22 = new GF16Matrix[params.getM()][params.getO()][params.getO()];
//        GF16Matrix temp1 = new GF16Matrix(params.getL());
//        GF16Matrix temp2 = new GF16Matrix(params.getL());
//
//        for (int i = 0; i < params.getM(); i++) {
//            for (int j = 0; j < params.getO(); j++) {
//                for (int k = 0; k < params.getO(); k++) {
//                    for (int idx = 0; idx < params.getV(); idx++) {
//                        GF16Matrix.mul(T12[idx][j], F12[i][idx][k], temp1);
//                        GF16Matrix.mul(P21[i][j][idx], T12[idx][k], temp2);
//                        GF16Matrix.add(temp1, temp2, temp1);
//                        GF16Matrix.add(P22[i][j][k], temp1, P22[i][j][k]);
//                    }
//                }
//            }
//        }
//
//        // Convert GF16 matrices to bytes
//        GF16Utils.convertGF16sToBytes(P22, outP22);
    }
}
