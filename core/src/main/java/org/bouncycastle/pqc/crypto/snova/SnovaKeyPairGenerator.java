package org.bouncycastle.pqc.crypto.snova;

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

        byte[] pk = new byte[params.getPublicKeyLength()];
        byte[] sk = new byte[params.getPrivateKeyLength()];

        byte[] ptPublicKeySeed = Arrays.copyOfRange(seedPair, 0, publicSeedLength);
        byte[] ptPrivateKeySeed = Arrays.copyOfRange(seedPair, publicSeedLength, seedPair.length);

        SnovaKeyElements keyElements = new SnovaKeyElements(params, engine);
        generateKeysCore(keyElements, ptPublicKeySeed, ptPrivateKeySeed);

        // Pack public key components
        System.arraycopy(ptPublicKeySeed, 0, pk, 0, ptPublicKeySeed.length);
        System.arraycopy(keyElements.publicKey.P22, 0, pk, ptPublicKeySeed.length, keyElements.publicKey.P22.length);

        if (params.isSkIsSeed())
        {
            sk = seedPair;
        }
        else
        {
            keyElements.encodeMergerInHalf(sk);
            System.arraycopy(seedPair, 0, sk, sk.length - seedLength, seedLength);
        }

        return new AsymmetricCipherKeyPair(
            new SnovaPublicKeyParameters(pk),
            new SnovaPrivateKeyParameters(sk)
        );
    }

    private void generateKeysCore(SnovaKeyElements keyElements, byte[] pkSeed, byte[] skSeed)
    {
        // Generate T12 matrix
        genSeedsAndT12(keyElements.T12, skSeed);

        // Generate map components
        genABQP(keyElements.map1, pkSeed, keyElements.fixedAbq);

        // Generate F matrices
        engine.genF(keyElements.map2, keyElements.map1, keyElements.T12);

        // Generate P22 matrix
        engine.genP22(keyElements.publicKey.P22, keyElements.T12, keyElements.map1.p21, keyElements.map2.f12);
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

    private void genABQP(MapGroup1 map1, byte[] pkSeed, byte[] fixedAbq)
    {
        int l = params.getL();
        int lsq = l * l;
        int m = params.getM();
        int alpha = params.getAlpha();
        int v = params.getV();
        int o = params.getO();
        int n = v + o;

        int gf16sPrngPublic = lsq * (2 * m * alpha + m * (n * n - m * m)) + l * 2 * m * alpha;
        byte[] qTemp = new byte[(m * alpha * lsq + m * alpha * lsq) / l];
        byte[] prngOutput = new byte[(gf16sPrngPublic + 1) >> 1];

        if (params.isPkExpandShake())
        {
            snovaShake(pkSeed, prngOutput.length, prngOutput);
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
        byte[] temp = new byte[gf16sPrngPublic - qTemp.length];
        GF16Utils.decode(prngOutput, temp, temp.length);
        map1.fill(temp);
        if (l >= 4)
        {
            GF16Utils.decode(prngOutput, temp.length >> 1, qTemp, 0, qTemp.length);

            // Post-processing for invertible matrices
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    engine.makeInvertibleByAddingAS(map1.aAlpha[pi][a], 0);
                }
            }
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    engine.makeInvertibleByAddingAS(map1.bAlpha[pi][a], 0);
                }
            }

            int ptArray = 0;
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    engine.genAFqS(qTemp, ptArray, map1.qAlpha1[pi][a], 0);
                    ptArray += l;
                }
            }
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    engine.genAFqS(qTemp, ptArray, map1.qAlpha2[pi][a], 0);
                    ptArray += l;
                }
            }
        }
        else
        {
            //TODO: fixedAbq fill more than aAlpha. bAlpha should be filled as well
            MapGroup1.fillAlpha(fixedAbq, 0, map1.aAlpha, m * o * alpha * lsq);
        }
    }

    public static void snovaShake(byte[] ptSeed, int outputBytes, byte[] out)
    {
        final int SHAKE128_RATE = 168; // 1344-bit rate = 168 bytes
        long blockCounter = 0;
        int offset = 0;
        int remaining = outputBytes;

        while (remaining > 0)
        {
            SHAKEDigest shake = new SHAKEDigest(128);

            // Process seed + counter
            shake.update(ptSeed, 0, ptSeed.length);
            updateWithCounter(shake, blockCounter);

            // Calculate bytes to generate in this iteration
            int bytesToGenerate = Math.min(remaining, SHAKE128_RATE);

            // Generate output (XOF mode)
            shake.doFinal(out, offset, bytesToGenerate);

            offset += bytesToGenerate;
            remaining -= bytesToGenerate;
            blockCounter++;
        }
    }

    private static void updateWithCounter(SHAKEDigest shake, long counter)
    {
        byte[] counterBytes = new byte[8];
        // Little-endian conversion
        for (int i = 0; i < 8; i++)
        {
            counterBytes[i] = (byte)(counter >> (i * 8));
        }
        shake.update(counterBytes, 0, 8);
    }
}
