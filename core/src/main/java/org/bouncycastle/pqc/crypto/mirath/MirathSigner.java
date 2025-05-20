package org.bouncycastle.pqc.crypto.mirath;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Shorts;

public class MirathSigner
    implements MessageSigner
{
    private static final byte domainSeparatorHash1 = 1;
    private static final byte domainSeparatorHash2Partial = 2;
    private static final byte domainSeparatorCmt = 3;
    private static final byte domainSeparatorPrg = 4;
    private static final byte domainSeparatorCommitment = 5;
    private SecureRandom random;
    private MirathParameters params;
    private MirathPublicKeyParameters pubKey;
    private MirathPrivateKeyParameters privKey;
    private MirathEngine engine;
    private SHA3Digest hash;
    private SHA3Digest digest;
    private boolean isFast;
    private int signatureBytes;
    private int n1Mask;
    private int n1Bits;
    private int n1Bytes;
    private int gamma;
    private int treeLeaves;
    private int tOpen;
    private int leavesSeedsOffset;
    private int maxOpen;
    private int blockLength;
    private int challenge2Bytes;
    private int hash2MaskBytes;
    private int hash2Mask;
    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (MirathPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (MirathPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (MirathPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
        engine = new MirathEngine(params);
        switch (engine.securityBytes)
        {
        case 16:
            hash = new SHA3Digest(256);
            digest = new SHA3Digest(256);
            break;
        case 24:
            hash = new SHA3Digest(384);
            digest = new SHA3Digest(384);
            break;
        case 32:
            hash = new SHA3Digest(512);
            digest = new SHA3Digest(512);
            break;
        default:
            throw new IllegalArgumentException("Unsupported security bytes size");
        }
        isFast = params.isFast();
        signatureBytes = params.getSignatureBytes();
        n1Mask = params.getN1Mask();
        n1Bits = params.getN1Bits();
        n1Bytes = params.getN1Bytes();
        gamma = engine.rho * engine.eA;
        tOpen = params.getTOpen();
        treeLeaves = params.getTreeLeaves();
        leavesSeedsOffset = treeLeaves - 1;
        maxOpen = 2 * tOpen;
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] sigMsg = new byte[params.getSignatureBytes() + message.length];
        byte[] sk = privKey.getEncoded();
        byte[] salt = new byte[engine.saltBytes];
        long ctr;
        // Phase 0: Initialization
        byte[][] path = new byte[maxOpen][engine.securityBytes];
        byte[] hMpc = new byte[2 * engine.securityBytes]; // hCom, hSh

        byte[] S = new byte[engine.ffSBytes];
        byte[] C = new byte[engine.ffCBytes];
        byte[] H = new byte[engine.ffHBytes];

        byte[] pk = new byte[params.getPublicKeyBytes()];
        byte[][] aux = new byte[engine.tau][engine.ffAuxBytes];
        byte[][] commitsIStar = new byte[engine.tau][2 * engine.securityBytes];
        byte[][] tree = new byte[params.getTreeLeaves() * 2 - 1][engine.securityBytes];
        byte[][] seeds = new byte[treeLeaves][engine.securityBytes];
        byte[] sample = new byte[engine.blockLength * engine.securityBytes]; //ffSBytes + ffCBytes + rho + (securityBytes - 1)

        byte[][][] commits = new byte[engine.tau][engine.n1][engine.securityBytes * 2];

        // Phase 1: Build and Commit Parallel Witness Shares
        // Step 1: Decompress secret key
        byte[] y = new byte[engine.ffYBytes];
        //sc, T, intermediate matrics
        byte[] sc = new byte[engine.mirathMatrixFFBytesSize(engine.m, engine.m - engine.r)];

        BlockCipher cipher = getBlockCipher(engine.securityBytes);
        // Expand matrices from seeds
        engine.mirathMatrixExpandSeedPublicMatrix(H, sk, engine.securityBytes);
        engine.mirathMatrixExpandSeedSecretMatrix(S, C, sk);

        // Compute y and build public key
        engine.mirathMatrixComputeY(y, S, C, H, sc);
        // emulateMPCMu: 12. sc = S * C
        engine.matrixFFProduct(sc, S, C, engine.m, engine.r, engine.m - engine.r);
        //unparsePublicKey
        System.arraycopy(sk, engine.securityBytes, pk, 0, engine.securityBytes);
        System.arraycopy(y, 0, pk, engine.securityBytes, engine.ffYBytes);
        random.nextBytes(salt);
        random.nextBytes(tree[0]);

        //hSh is hCom in this stage
        mirathMultivcCommit(cipher, hash, digest, seeds, hMpc, tree, commits, salt);

        if (params.isFast())
        {
            byte[][] SBase = new byte[engine.tau][engine.s];
            byte[][] CBase = new byte[engine.tau][engine.c];
            byte[][] vBase = new byte[engine.tau][engine.rho];
            byte[][] v = new byte[engine.tau][engine.rho];

            byte[] Gamma = new byte[gamma];
            byte[][] alphaMid = new byte[engine.tau][engine.rho];
            byte[][] alphaBase = new byte[engine.tau][engine.rho];
            // Temporary storage
            byte[] aux_s = new byte[engine.s]; // m * r
            byte[] aux_E = new byte[engine.baseMid]; // m * (m - r)
            byte[] aux_c = new byte[engine.c];
            byte[] eAeB = new byte[engine.m * engine.m];

            // Step 4: Commit to shares
            for (int e = 0; e < engine.tau; e++)
            {
                commitParallelSharings(cipher, SBase[e], CBase[e], vBase[e], v[e], e, aux[e], salt, S, C, seeds, sample);
            }
            computeFinalHash(digest, hMpc, salt, hMpc, aux);

            // Phase 2: MPC simulation
            // Step 5: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hMpc);

            // Steps 6-8: Emulate MPC for each tau
            for (int e = 0; e < engine.tau; e++)
            {
                emulateMPCMu(alphaBase[e], alphaMid[e], S, SBase[e], C, CBase[e], v[e], vBase[e], Gamma, H, sc, aux_s,
                    aux_E, aux_c, eAeB);
            }

            // Phase 3: Sharing Opening
            // Step 9: Hash MPC results
            mirathTcithHashMpc(digest, hMpc, pk, salt, message, hMpc, alphaMid, alphaBase);

            // Step 10: Open random share
            ctr = mirathTcithOpenRandomShare(path, commitsIStar, tree, commits, hMpc);

            // Step 11: Serialize signature
            unparseSignature(sigMsg, salt, ctr, hMpc, path, commitsIStar, aux, alphaMid);
        }
        else
        {
            short[][] SBase = new short[engine.tau][engine.s];
            short[][] CBase = new short[engine.tau][engine.c];
            short[][] vBase = new short[engine.tau][engine.rho];
            short[][] v = new short[engine.tau][engine.rho];

            short[] Gamma = new short[gamma];
            short[][] alphaMid = new short[engine.tau][engine.rho];
            short[][] alphaBase = new short[engine.tau][engine.rho];
            short[] v_rnd = new short[engine.rho];
            // Temporary storage
            short[] aux_E = new short[engine.baseMid];
            short[] aux_s = new short[engine.s];
            short[] aux_c = new short[engine.c];
            short[] eAeB = new short[engine.m * engine.m];
            // Step 4: Commit to shares
            for (int e = 0; e < engine.tau; e++)
            {
                commitParallelSharings(cipher, SBase[e], CBase[e], vBase[e], v[e], e, aux[e], salt, S, C, seeds, sample, v_rnd);
            }
            computeFinalHash(digest, hMpc, salt, hMpc, aux);
            // Phase 2: MPC simulation
            // Step 5: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hMpc);

            // Steps 6-8: Emulate MPC for each tau
            for (int e = 0; e < engine.tau; e++)
            {
                emulateMPCMu(alphaBase[e], alphaMid[e], S, SBase[e], C, CBase[e], v[e], vBase[e], Gamma, H, sc, aux_E,
                    aux_s, aux_c, eAeB);
            }

            // Phase 3: Sharing Opening
            // Step 9: Hash MPC results
            mirathTcithHashMpc(digest, hMpc, pk, salt, message, hMpc, alphaMid, alphaBase);

            // Step 10: Open random share
            ctr = mirathTcithOpenRandomShare(path, commitsIStar, tree, commits, hMpc);

            // Step 11: Serialize signature
            unparseSignature(sigMsg, salt, ctr, hMpc, path, commitsIStar, aux, alphaMid);
        }

        System.arraycopy(message, 0, sigMsg, params.getSignatureBytes(), message.length);

        return sigMsg;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        byte[] pk = pubKey.getEncoded();
        // Phase 0: Initialization
        byte[] salt = new byte[engine.saltBytes];
        byte[] hSh = new byte[2 * engine.securityBytes];
        byte[] hMpc = new byte[2 * engine.securityBytes];
        long[] ctr = new long[1];
        int[] iStar = new int[engine.tau];
        byte[] H = new byte[engine.ffHBytes];
        byte[] y = new byte[engine.ffYBytes];
        byte[][] commitsIStar = new byte[engine.tau][2 * engine.securityBytes];
        byte[][] path = new byte[maxOpen][engine.securityBytes];
        byte[][] aux = new byte[engine.tau][engine.ffAuxBytes];
        byte[] sample = new byte[2 * engine.blockLength * engine.securityBytes];
        BlockCipher cipher = getBlockCipher(engine.securityBytes);
        // Step 2: Decompress public key
        System.arraycopy(pk, engine.securityBytes, y, 0, engine.ffYBytes);
        engine.prng.update(pk, 0, engine.securityBytes);
        engine.prng.doFinal(H, 0, engine.ffHBytes);
        engine.mirathMatrixSetToFF(H, engine.eA, engine.k);
        //parseSignature part 1
        int tmpBits = (engine.m * engine.r + engine.r * (engine.m - engine.r) + engine.rho * engine.mu) * engine.tau;
        if (engine.isA)
        {
            tmpBits *= 4;
        }
        int modBits = tmpBits & 7;
        if (modBits != 0)
        {
            int mask = (1 << modBits) - 1;
            int lastByte = signature[signatureBytes - 1] & 0xFF;
            if ((lastByte & ~mask) != 0)
            {
                return false;
            }
        }
        int ptr = parseSignature1(signature, salt, hMpc, ctr, commitsIStar, path);
        byte[] ctrBytes;
        //computeParallelShares part 1
        byte[] vGrinding = new byte[engine.hash2MaskBytes]; // Adjust size if needed
        byte[] shakeInput = new byte[2 * engine.securityBytes + 8];

        // Prepare SHAKE input
        System.arraycopy(hMpc, 0, shakeInput, 0, 2 * engine.securityBytes);
        ctrBytes = Pack.longToLittleEndian(ctr);
        System.arraycopy(ctrBytes, 0, shakeInput, 2 * engine.securityBytes, 8);

        // Expand view challenge
        expandViewChallenge(iStar, vGrinding, shakeInput);

        // Reconstruct commitments
        byte[][] seeds = new byte[treeLeaves][engine.securityBytes];
        byte[][] tree = new byte[2 * treeLeaves - 1][engine.securityBytes];
        byte[][][] commits = new byte[engine.tau][engine.n1][engine.securityBytes * 2];
        int ret = multivcReconstruct(hash, digest, cipher, hSh, seeds, iStar, path, commitsIStar, salt, tree, commits);
        if ((ret & (discardInputChallenge2(vGrinding) == 0 ? 0 : 1)) != 0)
        {
            return false;
        }
        if (params.isFast())
        {
            byte[][] SShare = new byte[engine.tau][engine.s];
            byte[][] CShare = new byte[engine.tau][engine.c];
            byte[][] vShare = new byte[engine.tau][engine.rho];
            byte[] Gamma = new byte[gamma];
            byte[][] alphaMid = new byte[engine.tau][engine.rho];
            byte[][] alphaBase = new byte[engine.tau][engine.rho];
            // Initialize temporary buffers
            byte[] eAeB = new byte[engine.m * engine.m];

            // Step 1: Parse signature
            parseSignature(ptr, aux, alphaMid, signature);

            // Step 3: Compute parallel shares
            computeFinalHash(digest, hSh, salt, hSh, aux);
            for (int e = 0; e < engine.tau; e++)
            {
                computeShare(cipher, SShare[e], CShare[e], vShare[e], iStar[e], seeds, e, aux[e], salt, sample);
            }

            // Step 4: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 5-6: Emulate parties
            for (int e = 0; e < engine.tau; e++)
            {

                emulatePartyMu(alphaBase[e], iStar[e], SShare[e], CShare[e], vShare[e], Gamma, H, y, alphaMid[e], eAeB);
            }

            // Step 7: Compute MPC hash
            mirathTcithHashMpc(digest, hSh, pk, salt, message, hSh, alphaMid, alphaBase);
        }
        else
        {
            short[][] SShare = new short[engine.tau][engine.s];
            short[][] CShare = new short[engine.tau][engine.c];
            short[][] vShare = new short[engine.tau][engine.rho];
            short[] Gamma = new short[gamma];
            short[][] alphaMid = new short[engine.tau][engine.rho];
            short[][] alphaBase = new short[engine.tau][engine.rho];
            short[] vi = new short[engine.rho];
            short[] eAeB = new short[engine.m * engine.m];
            // Step 1: Parse signature
            parseSignature(ptr, aux, alphaMid, signature);

            // Step 3: Compute parallel shares
            computeFinalHash(digest, hSh, salt, hSh, aux);
            for (int e = 0; e < engine.tau; e++)
            {
                computeShare(cipher, SShare[e], CShare[e], vShare[e], iStar[e], seeds, e, aux[e], salt, sample, vi);
            }
            // Step 4: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 5-6: Emulate parties
            for (int e = 0; e < engine.tau; e++)
            {
                emulatePartyMu(alphaBase[e], iStar[e], SShare[e], CShare[e], vShare[e], Gamma, H, y, alphaMid[e], eAeB);
            }

            // Step 7: Compute MPC hash
            mirathTcithHashMpc(digest, hSh, pk, salt, message, hSh, alphaMid, alphaBase);
        }
        // Step 8: Verify hash equality
        return Arrays.equals(hMpc, hSh);
    }

    private void mirathMultivcCommit(BlockCipher cipher, SHA3Digest hash, SHA3Digest digest, byte[][] seeds, byte[] hCom,
                                     byte[][] tree, byte[][][] commits, byte[] salt)
    {
        // Initialize tree
        for (int i = 0; i < treeLeaves - 1; i++)
        {
            expandSeed(cipher, tree, 2 * i + 1, salt, i, tree[i]);
        }
        mirathGGMTreeGetLeaves(seeds, tree);

        hash.update(domainSeparatorCommitment);
        // Process commits
        for (int e = 0; e < engine.tau; e++)
        {
            for (int i = 0; i < engine.n1; i++)
            {
                tcithCommit(digest, commits[e][i], salt, e, i, seeds[tcithPsi(i, e)]);
                hash.update(commits[e][i], 0, 2 * engine.securityBytes);
            }
        }

        hash.doFinal(hCom, 0);
    }

    void expandSeed(BlockCipher cipher, byte[][] pairNode, int pos, byte[] salt, int idx, byte[] seed)
    {
        cipherInit(cipher, seed);
        byte[] msg = new byte[engine.securityBytes == 16 ? 16 : 32];
        System.arraycopy(salt, 0, msg, 0, engine.securityBytes);
        byte[] bytes = Pack.intToLittleEndian(idx);
        Bytes.xorTo(4, bytes, 0, msg, 1);
        msg[5] ^= domainSeparatorPrg;
        if (engine.securityBytes == 24)
        {
            byte[] output = new byte[32];
            cipher.processBlock(msg, 0, output, 0);
            System.arraycopy(output, 0, pairNode[pos], 0, engine.securityBytes);

            msg[0] ^= 0x01;
            org.bouncycastle.util.Arrays.clear(output);
            cipher.processBlock(msg, 0, output, 0);
            System.arraycopy(output, 0, pairNode[pos + 1], 0, engine.securityBytes);
        }
        else
        {
            cipher.processBlock(msg, 0, pairNode[pos], 0);
            msg[0] ^= 0x01;
            cipher.processBlock(msg, 0, pairNode[pos + 1], 0);
        }
    }

    void mirathGGMTreeGetLeaves(byte[][] output, byte[][] tree)
    {
        int firstLeaf = treeLeaves - 1;
        for (int i = firstLeaf; i < tree.length; i++)
        {
            System.arraycopy(tree[i], 0, output[i - firstLeaf], 0, engine.securityBytes);
        }
    }

    void cipherInit(BlockCipher cipher, byte[] seed)
    {
        byte[] keyBytes;
        if (engine.securityBytes == 16)
        {
            keyBytes = new byte[engine.securityBytes];
        }
        else
        {
            keyBytes = new byte[32];
        }
        System.arraycopy(seed, 0, keyBytes, 0, engine.securityBytes);
        cipher.init(true, new KeyParameter(keyBytes));
    }

    int tcithPsi(int i, int e)
    {
        return i * engine.tau + e;
    }

    void tcithCommit(SHA3Digest digest, byte[] commit, byte[] salt, int e, int i, byte[] seed)
    {
        digest.update(domainSeparatorCmt);
        digest.update(salt, 0, engine.saltBytes);
        digest.update(Pack.longToLittleEndian(tcithPsi(i, e)), 0, 4);
        digest.update(seed, 0, engine.securityBytes);
        digest.doFinal(commit, 0);
    }

    private BlockCipher getBlockCipher(int securityBytes)
    {
        return securityBytes == 16 ? AESEngine.newInstance() : new RijndaelEngine(256);
    }

    private void mirathTcithExpandMpcChallenge(byte[] Gamma, byte[] hSh)
    {
        engine.prng.update(hSh, 0, 2 * engine.securityBytes);
        engine.prng.doFinal(Gamma, 0, Gamma.length);
    }

    private void mirathTcithExpandMpcChallenge(short[] Gamma, byte[] hSh)
    {
        engine.prng.update(hSh, 0, 2 * engine.securityBytes);
        byte[] result = new byte[Gamma.length << 1];
        engine.prng.doFinal(result, 0, result.length);
        Pack.littleEndianToShort(result, 0, Gamma, 0, Gamma.length);
    }

    private void commitParallelSharings(BlockCipher cipher, byte[] SBase, byte[] CBase, byte[] vBase, byte[] v, int e,
                                       byte[] aux, byte[] salt, byte[] S, byte[] C, byte[][] seeds, byte[] sample)
    {
        System.arraycopy(S, 0, aux, 0, engine.ffSBytes);
        System.arraycopy(C, 0, aux, engine.ffSBytes, engine.ffCBytes);
        for (int i = 0; i < engine.n1; i++)
        {
            computeShare(cipher, sample, salt, seeds, i, e, i, SBase, CBase, vBase);

            // Performs S_acc = S_acc + S_rnd, C_acc = C_acc + C_rnd and v[e] = v[e] + v_rnd
            Bytes.xorTo(engine.ffSBytes, sample, aux);
            Bytes.xorTo(engine.ffCBytes, sample, engine.ffSBytes, aux, engine.ffSBytes);
            Bytes.xorTo(engine.rho, sample, engine.ffSBytes + engine.ffCBytes, v);
        }
    }

    public void commitParallelSharings(BlockCipher cipher, short[] S_base, short[] C_base, short[] v_base, short[] v, int e, byte[] aux,
                                       byte[] salt, byte[] S, byte[] C, byte[][] seeds, byte[] sample, short[] v_rnd)
    {
        System.arraycopy(S, 0, aux, 0, engine.ffSBytes);
        System.arraycopy(C, 0, aux, engine.ffSBytes, engine.ffCBytes);
        for (int i = 0; i < engine.n1; i++)
        {
            computeShare(cipher, sample, salt, seeds, i, e, v_rnd, i, S_base, C_base, v_base);

            // Performs S_acc = S_acc + S_rnd, C_acc = C_acc + C_rnd and v[e] = v[e] + v_rnd
            Bytes.xorTo(engine.ffSBytes, sample, aux);
            Bytes.xorTo(engine.ffCBytes, sample, engine.ffSBytes, aux, engine.ffSBytes);
            Shorts.xorTo(engine.rho, v_rnd, v);
        }
    }

    private void computeShare(BlockCipher cipher, byte[] sample, byte[] salt, byte[][] seeds, int i, int e, int i_star, byte[] S_share, byte[] C_share, byte[] v_share)
    {
        mirathExpandShare(cipher, sample, salt, seeds[tcithPsi(i, e)]);

        // Calculate scaling factor (XOR in GF(2^8))
        byte sc = (byte)i_star;

        // Add scaled components to shares
        engine.matrixFFMuAddMultipleFF(S_share, sc, sample, engine.m, engine.r);
        engine.matrixFFMuAddMultipleFF(C_share, sc, sample, engine.ffSBytes, engine.r, engine.m - engine.r);
        engine.mirathVectorFFMuAddMultiple(v_share, sc, sample, engine.ffSBytes + engine.ffCBytes, engine.rho);
    }

    private void computeShare(BlockCipher cipher, byte[] sample, byte[] salt, byte[][] seeds, int i, int e, short[] vi, int i_star, short[] S_share, short[] C_share, short[] v_share)
    {
        mirathExpandShare(cipher, sample, salt, seeds[tcithPsi(i, e)]);
        Pack.littleEndianToShort(sample, engine.ffSBytes + engine.ffCBytes, vi, 0, engine.rho >>> 1);
        if ((engine.rho & 1) != 0)
        {
            vi[engine.rho >>> 1] = (short)(sample[engine.ffSBytes + engine.ffCBytes + engine.rho - 1] & 0xff);
        }

        for (int j = 0; j < engine.rho; ++j)
        {
            // this works only for (q=2, mu=12) and (q=16, mu=3)
            vi[j] &= 0x0FFF;
        }

        // Calculate scaling factor (XOR in GF(2^8))
        short sc = (short)i_star;

        // Add scaled components to shares
        engine.matrixFFMuAddMultipleFF(S_share, sc, sample);
        engine.matrixFFMuAddMultipleFF(C_share, sc, sample, engine.ffSBytes);
        engine.mirathVectorFFMuAddMultiple(v_share, sc, vi, engine.rho);
    }

    void mirathExpandShare(BlockCipher cipher, byte[] sample, byte[] salt, byte[] seed)
    {
        int sampleOff = 0;
        cipherInit(cipher, seed);
        int blockSize = engine.securityBytes == 16 ? 16 : 32;
        byte[] ctr = new byte[blockSize];
        byte[] msg = new byte[blockSize];
        if (engine.securityBytes == 24)
        {
            byte[] output = new byte[32];
            for (int i = 0; i < engine.blockLength; i++)
            {
                ctr[0] = (byte)i;
                Bytes.xor(engine.securityBytes, ctr, salt, msg);
                cipher.processBlock(msg, 0, output, 0);
                System.arraycopy(output, 0, sample, sampleOff, engine.securityBytes);
                sampleOff += engine.securityBytes;
            }
        }
        else
        {
            for (int i = 0; i < engine.blockLength; i++)
            {
                ctr[0] = (byte)i;
                Bytes.xor(engine.securityBytes, ctr, salt, msg);
                cipher.processBlock(msg, 0, sample, sampleOff);
                sampleOff += engine.securityBytes;
            }
        }
        engine.mirathMatrixSetToFF(sample, engine.m, engine.r);
        engine.mirathMatrixSetToFF(sample, engine.ffSBytes, engine.r, engine.m - engine.r);
    }

    private void computeFinalHash(SHA3Digest digest, byte[] hSh, byte[] salt, byte[] hCom, byte[][] aux)
    {
        digest.update(domainSeparatorHash1);
        digest.update(salt, 0, salt.length);
        digest.update(hCom, 0, hCom.length);

        for (byte[] auxEntry : aux)
        {
            digest.update(auxEntry, 0, auxEntry.length);
        }

        digest.doFinal(hSh, 0);
    }

    private void emulateMPCMu(byte[] baseAlpha, byte[] midAlpha, byte[] S, byte[] S_rnd, byte[] C, byte[] C_rnd,
                              byte[] v, byte[] rnd_v, byte[] gamma, byte[] H, byte[] sc, byte[] aux_s, byte[] aux_E,
                              byte[] aux_c, byte[] eAeB)
    {
        // 1. aux_E = S_rnd * C_rnd
        engine.matrixFFMuProduct(eAeB, engine.s, S_rnd, C_rnd, engine.m, engine.r, engine.m - engine.r);

        // 2. Split codeword
        Arrays.fill(eAeB, 0, engine.s, (byte)0);
        System.arraycopy(eAeB, engine.s, aux_E, 0, aux_E.length);

        // 3. e_A + (H * e_B)
        engine.matrixFFMuProductFF1MuTo(eAeB, H, engine.eA, engine.k);

        // 5-6. gamma * [e_A + (H * e_B)] + rnd_V
        engine.matrixFFMuProductXor(baseAlpha, gamma, eAeB, rnd_v);

        // 8. aux_s = S_rnd + S
        engine.matrixFFMuAddMu1FF(aux_s, S_rnd, S, engine.m, engine.r);

        // 9. aux_c = C_rnd + C
        engine.matrixFFMuAddMu1FF(aux_c, C_rnd, C, engine.r, engine.m - engine.r);

        // 10-11. aux_E = aux_E + aux_s * aux_c
        engine.matrixFFMuProductTo(aux_E, aux_s, aux_c);

        // 13. aux_E = aux_E + sc
        engine.matrixFFMuAddMu1FFTo(aux_E, sc, engine.m, engine.m - engine.r);

        // 14. Split codeword again
        System.arraycopy(S_rnd, 0, eAeB, 0, engine.s);
        System.arraycopy(aux_E, 0, eAeB, engine.s, aux_E.length);

        // 15-16. e'_A + (H * e'_B)
        engine.matrixFFMuProductFF1MuTo(eAeB, H, engine.eA, engine.k);

        // 17 - 18 .gamma * [e_A + (H * e_B)] + v
        engine.matrixFFMuProductXor(midAlpha, gamma, eAeB, v);
    }

    private void emulateMPCMu(short[] baseAlpha, short[] midAlpha, byte[] S, short[] S_rnd, byte[] C, short[] C_rnd,
                              short[] v, short[] rnd_v, short[] gamma, byte[] H, byte[] sc, short[] aux_E, short[] aux_s,
                              short[] aux_c, short[] eAeB)
    {
        // 1. aux_E = S_rnd * C_rnd
        engine.matrixFFMuProduct(eAeB, engine.s, S_rnd, C_rnd, engine.m, engine.r, engine.m - engine.r);

        // 2. Split codeword
        Arrays.fill(eAeB, 0, engine.s, (byte)0);
        System.arraycopy(eAeB, engine.s, aux_E, 0, aux_E.length);

        // 3. e_A + (H * e_B)
        engine.matrixFFMuProductFF1MuTo(eAeB, H, engine.eA, engine.k);

        // 5-6. gamma * [e_A + (H * e_B)] + rnd_V
        engine.matrixFFMuProductXor(baseAlpha, gamma, eAeB, rnd_v);

        // 8. aux_s = S_rnd + S
        engine.matrixFFMuAddMu1FF(aux_s, S_rnd, S, engine.m, engine.r);

        // 9. aux_c = C_rnd + C
        engine.matrixFFMuAddMu1FF(aux_c, C_rnd, C, engine.r, engine.m - engine.r);

        // 10-11. aux_E = aux_E + aux_s * aux_c
        engine.matrixFFMuProductTo(aux_E, aux_s, aux_c);

        // 13. aux_E = aux_E + sc
        engine.matrixFFMuAddMu1FFTo(aux_E, sc, engine.m, engine.m - engine.r);

        // 14. Split codeword again
        System.arraycopy(S_rnd, 0, eAeB, 0, engine.s);
        System.arraycopy(aux_E, 0, eAeB, engine.s, aux_E.length);

        // 15-16. e'_A + (H * e'_B)
        engine.matrixFFMuProductFF1MuTo(eAeB, H, engine.eA, engine.k);

        // 17 - 18 .gamma * [e_A + (H * e_B)] + v
        engine.matrixFFMuProductXor(midAlpha, gamma, eAeB, v);
    }

    private void mirathTcithHashMpc(SHA3Digest digest, byte[] hMpc, byte[] pk, byte[] salt, byte[] msg, byte[] hSh,
                                    short[][] alphaMid, short[][] alphaBase)
    {
        HashMpcPart1(digest, pk, salt, msg, hSh);

        // Process alpha values
        for (int e = 0; e < engine.tau; e++)
        {
            byte[] tmp = Pack.shortToLittleEndian(alphaBase[e]);
            digest.update(tmp, 0, tmp.length);
            tmp = Pack.shortToLittleEndian(alphaMid[e]);
            digest.update(tmp, 0, tmp.length);
        }

        // Finalize hash
        digest.doFinal(hMpc, 0);
    }

    private void mirathTcithHashMpc(SHA3Digest digest, byte[] hMpc, byte[] pk, byte[] salt, byte[] msg, byte[] hSh,
                                    byte[][] alphaMid, byte[][] alphaBase)
    {
        HashMpcPart1(digest, pk, salt, msg, hSh);

        // Process alpha values
        for (int e = 0; e < engine.tau; e++)
        {
            digest.update(alphaBase[e], 0, alphaBase[e].length);
            digest.update(alphaMid[e], 0, alphaMid[e].length);
        }

        // Finalize hash
        digest.doFinal(hMpc, 0);
    }

    private void HashMpcPart1(SHA3Digest digest, byte[] pk, byte[] salt, byte[] msg, byte[] hSh)
    {
        // Initialize hash
        digest.update(domainSeparatorHash2Partial);
        digest.update(pk, 0, pk.length);
        digest.update(salt, 0, salt.length);
        digest.update(msg, 0, msg.length);
        digest.update(hSh, 0, hSh.length);
    }

    long mirathTcithOpenRandomShare(byte[][] path, byte[][] commitsIStar, byte[][] tree, byte[][][] commits, byte[] binding)
    {
        byte[] shakeInput = new byte[2 * engine.securityBytes + Long.BYTES];
        System.arraycopy(binding, 0, shakeInput, 0, 2 * engine.securityBytes);

        long ctr = 0;
        byte[] vGrinding = new byte[engine.hash2MaskBytes];

        while (true)
        {
            byte[] ctrBytes = Pack.longToLittleEndian(ctr);
            System.arraycopy(ctrBytes, 0, shakeInput, 2 * engine.securityBytes, Long.BYTES);

            int[] challenge = new int[engine.tau];
            expandViewChallenge(challenge, vGrinding, shakeInput);

            byte result = multivcOpen(path, commitsIStar, tree, commits, challenge);
            byte discard = discardInputChallenge2(vGrinding);

            if (discard == 0 && result == 0)
            {
                return ctr;
            }

            ctr++;
            org.bouncycastle.util.Arrays.fill(vGrinding, (byte)0);
            for (byte[] arr : path)
            {
                org.bouncycastle.util.Arrays.fill(arr, (byte)0);
            }
        }
    }

    private byte multivcOpen(byte[][] path, byte[][] commitsIStar, byte[][] tree, byte[][][] commits, int[] iStar)
    {
        List<Integer> pathIndexes = getPathIndexes(iStar);

        // Copy the seeds from the tree to the path

        for (int i = 0; i < pathIndexes.size(); i++)
        {
            System.arraycopy(tree[pathIndexes.get(i)], 0, path[i], 0, engine.securityBytes);
        }

        if (pathIndexes.size() > tOpen)
        {
            for (byte[] arr : path)
            {
                Arrays.fill(arr, (byte)0);
            }
            return 1;
        }

        for (int e = 0; e < engine.tau; e++)
        {
            System.arraycopy(commits[e][iStar[e]], 0, commitsIStar[e], 0, 2 * engine.securityBytes);
        }
        return 0;
    }

    private List<Integer> getPathIndexes(int[] iStar)
    {
        List<Integer> pathIndexes = new ArrayList<Integer>();

        for (int e = 0; e < engine.tau; e++)
        {
            int node = leavesSeedsOffset + tcithPsi(iStar[e], e);
            while (node > 0)
            {
                int pos = Collections.binarySearch(pathIndexes, node);
                if (pos >= 0)
                {
                    pathIndexes.remove(pos);
                    break;
                }
                else
                {
                    int sibling = (node & 1) == 1 ? node + 1 : node - 1;
                    if (pathIndexes.size() >= maxOpen)
                    {
                        return pathIndexes;
                    }
                    int insertPos = -pos - 1;
                    pathIndexes.add(insertPos, sibling);
                }
                node = getParent(node);
            }
        }
        return pathIndexes;
    }

    static int getParent(int nodeIndex)
    {
        return (nodeIndex - 1) >>> 1;
    }

    void expandViewChallenge(int[] challenge, byte[] vGrinding, byte[] input)
    {
        engine.prng.update(input, 0, input.length);

        byte[] random = new byte[engine.challenge2Bytes + engine.hash2MaskBytes];
        engine.prng.doFinal(random, 0, random.length);

        // Extract v_grinding and apply mask
        System.arraycopy(random, engine.challenge2Bytes, vGrinding, 0, engine.hash2MaskBytes);
        vGrinding[engine.hash2MaskBytes - 1] &= engine.hash2Mask;
        org.bouncycastle.util.Arrays.fill(random, engine.challenge2Bytes, random.length, (byte)0);

        int randomOffset = 0;

        // Process N1 challenges
        for (int e = 0; e < engine.tau; e++)
        {
            byte[] block = org.bouncycastle.util.Arrays.copyOfRange(random, randomOffset, randomOffset + n1Bytes);
            block[n1Bytes - 1] &= n1Mask;

            challenge[e] = isFast ? (block[0] & 0xff) : Pack.littleEndianToShort(block, 0);

            // Shift right by N1_BITS
            for (int j = 0; j < n1Bits; j++)
            {
                for (int i = 0; i < engine.challenge2Bytes - 1; i++)
                {
                    random[i] = (byte)(((random[i] & 0xff) >>> 1) ^ ((random[i + 1] & 0xff) << 7));
                }
                random[engine.challenge2Bytes - 1] = (byte)((random[engine.challenge2Bytes - 1] & 0xff) >>> 1);
            }
        }
    }

    public byte discardInputChallenge2(byte[] vGrinding)
    {
        byte output = 0x00;
        byte mask = (byte)engine.hash2Mask;

        for (int i = 0; i < engine.hash2MaskBytes; i++)
        {
            if (i > 0)
            {
                mask = (byte)0xFF;
            }
            if ((vGrinding[i] & mask) != 0)
            {
                output = 0x01;
                break;
            }
        }
        return output;
    }

    public void unparseSignature(byte[] signature, byte[] salt, long ctr, byte[] hash2, byte[][] path, byte[][] commitsIStar,
                                 byte[][] aux, byte[][] midAlpha)
    {
        unparseSignature(signature, salt, ctr, hash2, path, commitsIStar);

        // Pack field elements
        int offPtr = 8; // Tracks bits remaining in current byte

        for (int e = 0; e < engine.tau; e++)
        {
            engine.col = 0;
            // Process R columns (M x R matrix)
            offPtr = engine.parse(signature, aux[e], offPtr, engine.r, engine.nRowsBytes1, engine.onCol1);

            // Process (N-R) columns (R x (N-R) matrix)
            offPtr = engine.parse(signature, aux[e], offPtr, engine.m - engine.r, engine.nRowsBytes2, engine.onCol2);

            // Process midAlpha (GF256 elements)
            for (int i = 0; i < engine.rho; i++)
            {
                byte entry = midAlpha[e][i];
                int shift = 8 - offPtr;
                signature[engine.ptr] |= (byte)((entry & 0xff) << shift);
                engine.ptr++;

                if (offPtr < 8)
                {
                    signature[engine.ptr] = (byte)((entry & 0xff) >>> offPtr);
                }
            }
        }
    }

    private void unparseSignature(byte[] signature, byte[] salt, long ctr, byte[] hash2, byte[][] path, byte[][] commitsIStar)
    {
        // Copy salt
        System.arraycopy(salt, 0, signature, 0, engine.saltBytes);
        engine.ptr = engine.saltBytes;

        // Copy counter (little-endian)
        byte[] ctrBytes = Pack.longToLittleEndian(ctr);
        System.arraycopy(ctrBytes, 0, signature, engine.ptr, 8);
        engine.ptr += 8;

        // Copy hash2
        System.arraycopy(hash2, 0, signature, engine.ptr, 2 * engine.securityBytes);
        engine.ptr += 2 * engine.securityBytes;

        // Copy path
        for (int i = 0; i < tOpen; ++i)
        {
            System.arraycopy(path[i], 0, signature, engine.ptr, engine.securityBytes);
            engine.ptr += engine.securityBytes;
        }

        // Copy commits_i_star
        for (byte[] commit : commitsIStar)
        {
            System.arraycopy(commit, 0, signature, engine.ptr, 2 * engine.securityBytes);
            engine.ptr += 2 * engine.securityBytes;
        }
    }

    public void unparseSignature(byte[] signature, byte[] salt, long ctr, byte[] hash2, byte[][] path, byte[][] commitsIStar,
                                 byte[][] aux, short[][] midAlpha)
    {
        unparseSignature(signature, salt, ctr, hash2, path, commitsIStar);

        // Pack field elements
        int offPtr = 8; // Tracks bits remaining in current byte

        for (int e = 0; e < engine.tau; e++)
        {
            engine.col = 0;
            // Process R columns (M x R matrix)
            offPtr = engine.parse(signature, aux[e], offPtr, engine.r, engine.nRowsBytes1, engine.onCol1);

            // Process (N-R) columns (R x (N-R) matrix)
            offPtr = engine.parse(signature, aux[e], offPtr, engine.m - engine.r, engine.nRowsBytes2, engine.onCol2);

            int onMu = 4;
            short maskHighMu = 0x0F00;
            // Process midAlpha (GF256 elements)
            for (int i = 0; i < engine.rho; i++)
            {
                short entry = midAlpha[e][i];
                int shift = 8 - offPtr;
                byte entryLow = (byte)(entry & 0x00ff);
                byte entryHigh = (byte)((entry & maskHighMu) >>> 8);
                signature[engine.ptr] |= (byte)((entryLow & 0xff) << shift);
                engine.ptr++;
                signature[engine.ptr] = (byte)((entryLow & 0xff) >>> offPtr);
                signature[engine.ptr] |= (byte)((entryHigh & 0xff) << shift);
                if (offPtr > onMu)
                {
                    offPtr = offPtr - onMu;
                }
                else if (offPtr == onMu)
                {
                    engine.ptr++;
                    signature[engine.ptr] = 0;
                    offPtr = 8;
                }
                else
                {
                    engine.ptr++;
                    signature[engine.ptr] = (byte)((entryHigh & 0xff) >>> offPtr);
                    offPtr = offPtr + 8 - onMu;
                }
            }
        }
    }
    
    int multivcReconstruct(SHA3Digest hash, SHA3Digest digest, BlockCipher cipher, byte[] hCom, byte[][] seeds,
                           int[] iStar, byte[][] path, byte[][] commitsIStar, byte[] salt, byte[][] tree, byte[][][] commits)
    {
        List<Integer> pathIndexes = getPathIndexes(iStar);
        int pathLength = 0;
        final byte[] zeroArray = new byte[engine.securityBytes]; // Automatically initialized to all zeros

        for (int i = 0; i < tOpen; i++)
        {
            if (!org.bouncycastle.util.Arrays.areEqual(path[i], zeroArray))
            {
                pathLength++;
            }
        }

        // Process tree nodes
        int k = 0;
        int parentNode = pathIndexes.size() < maxOpen ? getParent(pathIndexes.get(k)) : -1;
        boolean[] valid = new boolean[treeLeaves + 1];

        for (int i = 0; i < treeLeaves - 1; i++)
        {
            if (i == parentNode)
            {
                int idx = pathIndexes.get(k);
                System.arraycopy(path[k], 0, tree[idx], 0, engine.securityBytes);
                if (i < treeLeaves / 2)
                {
                    valid[idx] = true;
                }
                k++;
                if (k < pathLength)
                {
                    parentNode = getParent(pathIndexes.get(k));
                }
            }
            else
            {
                if (valid[i])
                {
                    int child0 = 2 * i + 1;
                    expandSeed(cipher, tree, child0, salt, i, tree[i]);
                    if (i < treeLeaves / 2)
                    {
                        valid[child0] = true;
                        valid[child0 + 1] = true;
                    }
                }
            }
        }

        if (k != pathLength)
        {
            return -1;
        }

        mirathGGMTreeGetLeaves(seeds, tree);

        hash.update(domainSeparatorCommitment);
        // Process commits
        for (int e = 0; e < engine.tau; e++)
        {
            System.arraycopy(commitsIStar[e], 0, commits[e][iStar[e]], 0, 2 * engine.securityBytes);
            for (int i = 0; i < engine.n1; i++)
            {
                if (i != iStar[e])
                {
                    tcithCommit(digest, commits[e][i], salt, e, i, seeds[tcithPsi(i, e)]);
                }
                hash.update(commits[e][i], 0, 2 * engine.securityBytes);
            }
        }

        hash.doFinal(hCom, 0);

        return 0;
    }

    private int parseSignature1(byte[] signature, byte[] salt, byte[] hMpc, long[] ctr,
                                byte[][] commitsIStar, byte[][] path)
    {
        int ptr = 0;
        // Copy salt
        System.arraycopy(signature, ptr, salt, 0, engine.saltBytes);
        ptr += engine.saltBytes;
        // Copy counter (little-endian)
        ctr[0] = Pack.littleEndianToLong(signature, ptr);
        ptr += 8;
        // Copy hash2
        System.arraycopy(signature, ptr, hMpc, 0, 2 * engine.securityBytes);
        ptr += 2 * engine.securityBytes;

        // Copy path
        for (int i = 0; i < tOpen; i++)
        {
            System.arraycopy(signature, ptr, path[i], 0, engine.securityBytes);
            ptr += engine.securityBytes;
        }

        // Copy commits_i_star
        for (int e = 0; e < engine.tau; e++)
        {
            System.arraycopy(signature, ptr, commitsIStar[e], 0, 2 * engine.securityBytes);
            ptr += 2 * engine.securityBytes;
        }
        return ptr;
    }

    private int parseSignatureToAux(byte[] aux, byte[] signature, int offPtr, int loop, int nRowsBytes, int onCol)
    {
        for (int j = 0; j < loop; j++)
        {
            aux[engine.col] = (byte)((signature[engine.ptr] & 0xff) >>> (8 - offPtr));
            for (int i = 0; i < nRowsBytes - 1; ++i)
            {
                engine.ptr++;
                aux[engine.col] |= (byte)((signature[engine.ptr] & 0xff) << offPtr);
                engine.col++;
                aux[engine.col] = (byte)((signature[engine.ptr] & 0xff) >>> (8 - offPtr));
            }
            if (offPtr <= onCol)
            {
                engine.ptr++;
                aux[engine.col] |= (byte)((signature[engine.ptr] & 0xff) << offPtr);
            }
            aux[engine.col] &= (0xff >>> (8 - onCol));
            offPtr = 8 - ((onCol - offPtr) & 7);
            engine.col++;
        }
        return offPtr;
    }
    
    private void parseSignature(int pos, byte[][] aux, byte[][] midAlpha, byte[] signature)
    {
        int offPtr = 8; // Tracks bits remaining in current byte
        engine.ptr = pos;
        for (int e = 0; e < engine.tau; e++)
        {
            engine.col = 0;
            // Process R columns (M x R matrix)
            offPtr = parseSignatureToAux(aux[e], signature, offPtr, engine.r, engine.nRowsBytes1, engine.onCol1);

            // Process (N-R) columns (R x (N-R) matrix)
            offPtr = parseSignatureToAux(aux[e], signature, offPtr, engine.m - engine.r, engine.nRowsBytes2, engine.onCol2);

            // Process midAlpha (GF256 elements)
            for (int i = 0; i < engine.rho; i++)
            {
                byte entry = (byte)((signature[engine.ptr] & 0xff) >>> (8 - offPtr));
                engine.ptr++;
                entry |= (byte)((signature[engine.ptr] & 0xff) << offPtr);
                midAlpha[e][i] = entry;
            }
        }
    }

    public void parseSignature(int pos, byte[][] aux, short[][] midAlpha, byte[] signature)
    {
        // Unpack field elements
        int offPtr = 8; // Tracks bits remaining in current byte
        engine.ptr = pos;
        int onMu = 4;
        short maskHighMu = 0x0F;
        for (int e = 0; e < engine.tau; e++)
        {
            engine.col = 0;
            // Process R columns (M x R matrix)
            offPtr = parseSignatureToAux(aux[e], signature, offPtr, engine.r, engine.nRowsBytes1, engine.onCol1);

            // Process (N-R) columns (R x (N-R) matrix)
            offPtr = parseSignatureToAux(aux[e], signature, offPtr, engine.m - engine.r, engine.nRowsBytes2, engine.onCol2);

            // Process midAlpha (GF256 elements)
            for (int i = 0; i < engine.rho; i++)
            {
                byte entryLow = (byte)((signature[engine.ptr] & 0xff) >>> (8 - offPtr));
                engine.ptr++;
                entryLow |= ((signature[engine.ptr] & 0xff) << offPtr);
                byte entryHigh = (byte)((signature[engine.ptr] & 0xff) >>> (8 - offPtr));
                if (offPtr > onMu)
                {
                    entryHigh &= maskHighMu;
                    offPtr -= onMu;
                }
                else if (offPtr == onMu)
                {
                    engine.ptr++;
                    offPtr = 8;
                }
                else
                {
                    engine.ptr++;
                    entryHigh |= (byte)(((signature[engine.ptr] & 0xff) << offPtr) & maskHighMu);
                    offPtr = offPtr + 8 - onMu;
                }
                midAlpha[e][i] = (short)(((entryHigh & 0xff) << 8) | (entryLow & 0xff));
            }
        }
    }

    void computeShare(BlockCipher cipher, byte[] S_share, byte[] C_share, byte[] v_share, int i_star, byte[][] seeds, int e, byte[] aux,
                      byte[] salt, byte[] sample)
    {
        // Determine matrix dimensions based on parameter version
        for (int i = 0; i < engine.n1; i++)
        {
            if (i != i_star)
            {
                computeShare(cipher, sample, salt, seeds, i, e, (i_star ^ i), S_share, C_share, v_share);
            }
        }

        // Add final scaled auxiliary components
        byte phi_i = (byte)i_star;
        engine.matrixFFMuAddMultipleFF(S_share, phi_i, aux, engine.m, engine.r);
        engine.matrixFFMuAddMultipleFF(C_share, phi_i, aux, engine.ffSBytes, engine.r, engine.m - engine.r);
    }

    void computeShare(BlockCipher cipher, short[] S_share, short[] C_share, short[] v_share, int i_star, byte[][] seeds, int e, byte[] aux,
                      byte[] salt, byte[] sample, short[] vi)
    {
        // Determine matrix dimensions based on parameter version
        for (int i = 0; i < engine.n1; i++)
        {
            if (i != i_star)
            {
                computeShare(cipher, sample, salt, seeds, i, e, vi, (i_star ^ i), S_share, C_share, v_share);
            }
        }

        // Add final scaled auxiliary components
        short phi_i = (short)i_star;
        engine.matrixFFMuAddMultipleFF(S_share, phi_i, aux);
        engine.matrixFFMuAddMultipleFF(C_share, phi_i, aux, engine.ffSBytes);
    }

    public void emulatePartyMu(byte[] baseAlpha, int p, byte[] S_share, byte[] C_share, byte[] v_share,
                               byte[] gamma, byte[] H, byte[] y, byte[] midAlpha, byte[] eAeB)
    {
        // p * S_share (accumulated in Ts)
        engine.mirathMatrixFFMuAddMultiple2(eAeB, (byte)p, S_share);

        // S_share * C_share -> aux
        engine.matrixFFMuProduct(eAeB, engine.s, S_share, C_share, engine.m, engine.r, engine.m - engine.r);

        // e_A + (H * e_B)
        engine.matrixFFMuProductFF1MuTo(eAeB, H, engine.eA, engine.k);

        // - y * p² (equivalent to XOR in GF)
        byte pSquared = engine.mirathFFMuMult((byte)p, (byte)p);
        engine.mirathVectorFFMuAddMultipleFF(eAeB, pSquared, y, engine.eA);

        // gamma * tmp -> baseAlpha
        engine.matrixFFMuProductXor(baseAlpha, gamma, eAeB, v_share);

        // Add mid_alpha * p
        engine.mirathVectorFFMuAddMultiple(baseAlpha, (byte)p, midAlpha, engine.rho);
    }

    public void emulatePartyMu(short[] baseAlpha, int p, short[] S_share, short[] C_share, short[] v_share,
                               short[] gamma, byte[] H, byte[] y, short[] midAlpha, short[] eAeB)
    {
        // p * S_share (accumulated in Ts)
        engine.mirathMatrixFFMuAddMultiple2(eAeB, (short)p, S_share);

        // S_share * C_share -> aux
        engine.matrixFFMuProduct(eAeB, engine.s, S_share, C_share, engine.m, engine.r, engine.m - engine.r);

        // e_A + (H * e_B)
        engine.matrixFFMuProductFF1MuTo(eAeB, H, engine.eA, engine.k);

        // - y * p² (equivalent to XOR in GF)
        short pSquared = engine.mirathFFMuMult((short)p, (short)p);
        engine.mirathVectorFFMuAddMultipleFF(eAeB, pSquared, y, engine.eA);

        // gamma * tmp -> baseAlpha
        engine.matrixFFMuProductXor(baseAlpha, gamma, eAeB, v_share);

        // Add mid_alpha * p
        engine.mirathVectorFFMuAddMultiple(baseAlpha, (short)p, midAlpha, engine.rho);
    }
}
