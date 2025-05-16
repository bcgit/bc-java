package org.bouncycastle.pqc.crypto.mirath;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Shorts;

public class MirathSigner
    implements MessageSigner
{
    private SecureRandom random;
    private MirathParameters params;
    private MirathPublicKeyParameters pubKey;
    private MirathPrivateKeyParameters privKey;
    private MirathEngine engine;
    private static final byte domainSeparatorHash1 = 1;

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
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] sigMsg = new byte[params.getSignatureBytes() + message.length];
        byte[] sk = privKey.getEncoded();
        byte[] salt = new byte[engine.saltBytes];
        byte[] rseed = new byte[engine.securityBytes];
        long ctr;
        // Phase 0: Initialization
        byte[][] path = new byte[engine.maxOpen][engine.securityBytes];
        byte[] hMpc = new byte[2 * engine.securityBytes];

        byte[] S = new byte[engine.ffSBytes];
        byte[] C = new byte[engine.ffCBytes];
        byte[] H = new byte[engine.ffHBytes];

        byte[] pk = new byte[params.getPublicKeyBytes()];
        byte[][] aux = new byte[engine.tau][engine.ffAuxBytes];
        byte[] hSh = new byte[2 * engine.securityBytes];
        byte[][] commitsIStar = new byte[engine.tau][2 * engine.securityBytes];
        byte[][] tree = new byte[params.getTreeLeaves() * 2 - 1][engine.securityBytes];
        byte[][] seeds = new byte[engine.treeLeaves][engine.securityBytes];
        byte[] sample = new byte[engine.blockLength * engine.securityBytes];

        byte[][][] commits = new byte[engine.tau][engine.n1][engine.securityBytes * 2];

        // Phase 1: Build and Commit Parallel Witness Shares
        // Step 1: Decompress secret key
        //engine.mirathMatrixDecompressSecretKey(S, C, H, pk, sk);
        byte[] seedSk = org.bouncycastle.util.Arrays.copyOfRange(sk, 0, engine.securityBytes);
        byte[] seedPk = org.bouncycastle.util.Arrays.copyOfRange(sk, engine.securityBytes, 2 * engine.securityBytes);
        byte[] y = new byte[engine.ffYBytes];

        byte[] sc = new byte[engine.mirathMatrixFFBytesSize(engine.m, engine.m - engine.r)];
        SHA3Digest hash = engine.getSHA3Digest();
        SHA3Digest digest = engine.getSHA3Digest();
        BlockCipher cipher = getBlockCipher(engine.securityBytes);
        // Expand matrices from seeds
        engine.mirathMatrixExpandSeedPublicMatrix(H, seedPk);
        engine.mirathMatrixExpandSeedSecretMatrix(S, C, seedSk);

        // Compute y and build public key
        engine.mirathMatrixComputeY(y, S, C, H);
        // emulateMPCMu: 12. sc = S * C
        engine.matrixFFProduct(sc, S, C, engine.m, engine.r, engine.m - engine.r);
        //unparsePublicKey
        System.arraycopy(seedPk, 0, pk, 0, engine.securityBytes);
        System.arraycopy(y, 0, pk, engine.securityBytes, engine.ffYBytes);
        random.nextBytes(salt);
        random.nextBytes(rseed);

        //hSh is hCom in this stage
        mirathMultivcCommit(cipher, engine, hash, digest, seeds, hSh, tree, commits, salt, rseed);

        if (params.isFast())
        {
            byte[][] SBase = new byte[engine.tau][engine.s];
            byte[][] CBase = new byte[engine.tau][engine.c];
            byte[][] vBase = new byte[engine.tau][engine.rho];
            byte[][] v = new byte[engine.tau][engine.rho];

            byte[] Gamma = new byte[engine.gamma];
            byte[][] alphaMid = new byte[engine.tau][engine.rho];
            byte[][] alphaBase = new byte[engine.tau][engine.rho];

            // Step 4: Commit to shares
            for (int e = 0; e < engine.tau; e++)
            {
                commitParallelSharings(cipher, SBase[e], CBase[e], vBase[e], v[e], e, aux[e], salt, S, C, seeds, sample);
            }
            computeFinalHash(digest, hSh, salt, hSh, aux);

            // Phase 2: MPC simulation
            // Step 5: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 6-8: Emulate MPC for each tau
            for (int e = 0; e < engine.tau; e++)
            {
                engine.emulateMPCMu(alphaBase[e], alphaMid[e], S, SBase[e], C, CBase[e], v[e], vBase[e], Gamma, H, sc);
            }

            // Phase 3: Sharing Opening
            // Step 9: Hash MPC results
            engine.mirathTcithHashMpc(digest, hMpc, pk, salt, message, hSh, alphaMid, alphaBase);

            // Step 10: Open random share
            ctr = engine.mirathTcithOpenRandomShare(path, commitsIStar, tree, commits, hMpc);

            // Step 11: Serialize signature
            engine.unparseSignature(sigMsg, salt, ctr, hMpc, path, commitsIStar, aux, alphaMid);
        }
        else
        {
            short[][] SBase = new short[engine.tau][engine.s];
            short[][] CBase = new short[engine.tau][engine.c];
            short[][] vBase = new short[engine.tau][engine.rho];
            short[][] v = new short[engine.tau][engine.rho];

            short[] Gamma = new short[engine.gamma];
            short[][] alphaMid = new short[engine.tau][engine.rho];
            short[][] alphaBase = new short[engine.tau][engine.rho];
            short[] v_rnd = new short[engine.rho];
            // Step 4: Commit to shares
            for (int e = 0; e < engine.tau; e++)
            {
                commitParallelSharings(cipher, SBase[e], CBase[e], vBase[e], v[e], e, aux[e], salt, S, C, seeds, sample, v_rnd);
            }
            computeFinalHash(digest, hSh, salt, hSh, aux);
            // Phase 2: MPC simulation
            // Step 5: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 6-8: Emulate MPC for each tau
            for (int e = 0; e < engine.tau; e++)
            {
                engine.emulateMPCMu(alphaBase[e], alphaMid[e], S, SBase[e], C, CBase[e], v[e], vBase[e], Gamma, H, sc);
            }

            // Phase 3: Sharing Opening
            // Step 9: Hash MPC results
            engine.mirathTcithHashMpc(digest, hMpc, pk, salt, message, hSh, alphaMid, alphaBase);

            // Step 10: Open random share
            ctr = engine.mirathTcithOpenRandomShare(path, commitsIStar, tree, commits, hMpc);

            // Step 11: Serialize signature
            engine.unparseSignature(sigMsg, salt, ctr, hMpc, path, commitsIStar, aux, alphaMid);
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
        byte[] hMpcPrime = new byte[2 * engine.securityBytes];
        byte[] hMpc = new byte[2 * engine.securityBytes];
        long[] ctr = new long[1];
        int[] iStar = new int[engine.tau];
        byte[] H = new byte[engine.ffHBytes];
        byte[] y = new byte[engine.ffYBytes];
        byte[][] commitsIStar = new byte[engine.tau][2 * engine.securityBytes];
        byte[][] path = new byte[engine.maxOpen][engine.securityBytes];
        byte[][] aux = new byte[engine.tau][engine.ffAuxBytes];
        byte[] sample = new byte[2 * engine.blockLength * engine.securityBytes];
        SHA3Digest hash = engine.getSHA3Digest();
        SHA3Digest digest = engine.getSHA3Digest();
        BlockCipher cipher = getBlockCipher(engine.securityBytes);
        // Step 2: Decompress public key
        System.arraycopy(pk, engine.securityBytes, y, 0, engine.ffYBytes);
        engine.prng.update(pk, 0, engine.securityBytes);
        engine.prng.doFinal(H, 0, engine.mirathMatrixFFBytesSize(engine.eA, engine.k));
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
            int lastByte = signature[engine.signatureBytes - 1] & 0xFF;
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
        engine.expandViewChallenge(iStar, vGrinding, shakeInput);

        // Reconstruct commitments
        byte[][] seeds = new byte[engine.treeLeaves][engine.securityBytes];
        byte[][] tree = new byte[2 * engine.treeLeaves - 1][engine.securityBytes];
        byte[][][] commits = new byte[engine.tau][engine.n1][engine.securityBytes * 2];
        int ret = engine.multivcReconstruct(hash, digest, cipher, hSh, seeds, iStar, path, commitsIStar, salt, tree, commits);
        if ((ret & (engine.discardInputChallenge2(vGrinding) == 0 ? 0 : 1)) != 0)
        {
            return false;
        }
        if (params.isFast())
        {
            byte[][] SShare = new byte[engine.tau][engine.s];
            byte[][] CShare = new byte[engine.tau][engine.c];
            byte[][] vShare = new byte[engine.tau][engine.rho];
            byte[] Gamma = new byte[engine.gamma];
            byte[][] alphaMid = new byte[engine.tau][engine.rho];
            byte[][] alphaBase = new byte[engine.tau][engine.rho];

            // Step 1: Parse signature
            engine.parseSignature(ptr, aux, alphaMid, signature);

            // Step 3: Compute parallel shares
            computeFinalHash(digest, hSh, salt, hSh, aux);
            for (int e = 0; e < engine.tau; e++)
            {
                engine.computeShare(cipher, SShare[e], CShare[e], vShare[e], iStar[e], seeds, e, aux[e], salt, sample);
            }

            // Step 4: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 5-6: Emulate parties
            for (int e = 0; e < engine.tau; e++)
            {
                engine.emulatePartyMu(alphaBase[e], iStar[e], SShare[e], CShare[e],
                    vShare[e], Gamma, H, y, alphaMid[e]);
            }

            // Step 7: Compute MPC hash
            engine.mirathTcithHashMpc(digest, hMpcPrime, pk, salt, message, hSh, alphaMid, alphaBase);
        }
        else
        {
            short[][] SShare = new short[engine.tau][engine.s];
            short[][] CShare = new short[engine.tau][engine.c];
            short[][] vShare = new short[engine.tau][engine.rho];
            short[] Gamma = new short[engine.gamma];
            short[][] alphaMid = new short[engine.tau][engine.rho];
            short[][] alphaBase = new short[engine.tau][engine.rho];
            short[] vi = new short[engine.rho];
            // Step 1: Parse signature
            engine.parseSignature(ptr, aux, alphaMid, signature);

            // Step 3: Compute parallel shares
            computeFinalHash(digest, hSh, salt, hSh, aux);
            for (int e = 0; e < engine.tau; e++)
            {
                engine.computeShare(cipher, SShare[e], CShare[e], vShare[e], iStar[e], seeds, e, aux[e], salt, sample, vi);
            }
            // Step 4: Expand MPC challenge
            mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 5-6: Emulate parties
            for (int e = 0; e < engine.tau; e++)
            {
                engine.emulatePartyMu(alphaBase[e], iStar[e], SShare[e], CShare[e],
                    vShare[e], Gamma, H, y, alphaMid[e]);
            }

            // Step 7: Compute MPC hash
            engine.mirathTcithHashMpc(digest, hMpcPrime, pk, salt, message, hSh, alphaMid, alphaBase);
        }
        // Step 8: Verify hash equality
        return Arrays.equals(hMpc, hMpcPrime);
    }

    private int parseSignature1(byte[] signature, byte[] salt, byte[] hMpc, long[] ctr,
                                byte[][] commitsIStar, byte[][] path)
    {
        int ptr = 0;
        // Copy salt
        System.arraycopy(signature, ptr, salt, 0, engine.saltBytes);
        ptr += engine.saltBytes;
        // Copy counter (little-endian)
        byte[] ctrBytes = new byte[8];
        System.arraycopy(signature, ptr, ctrBytes, 0, 8);
        ctr[0] = Pack.littleEndianToLong(ctrBytes, 0);
        ptr += 8;
        // Copy hash2
        System.arraycopy(signature, ptr, hMpc, 0, 2 * engine.securityBytes);
        ptr += 2 * engine.securityBytes;

        // Copy path
        for (int i = 0; i < engine.tOpen; i++)
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

    private void mirathMultivcCommit(BlockCipher cipher, MirathEngine engine, SHA3Digest hash, SHA3Digest digest, byte[][] seeds, byte[] hCom, byte[][] tree,
                                     byte[][][] commits, byte[] salt, byte[] rseed)
    {
        // Initialize tree
        System.arraycopy(rseed, 0, tree[0], 0, engine.securityBytes);
        for (int i = 0; i < engine.treeLeaves - 1; i++)
        {
            engine.mirathExpandSeed(cipher, tree, 2 * i + 1, salt, i, tree[i]);
        }
        engine.mirathGGMTreeGetLeaves(seeds, tree);

        hash.update(MirathEngine.domainSeparatorCommitment);
        // Process commits
        for (int e = 0; e < engine.tau; e++)
        {
            for (int i = 0; i < engine.n1; i++)
            {
                engine.mirathTcithCommit(digest, commits[e][i], salt, e, i, seeds[engine.mirathTcithPsi(i, e)]);
                hash.update(commits[e][i], 0, 2 * engine.securityBytes);
            }
        }

        hash.doFinal(hCom, 0);
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

    public void commitParallelSharings(BlockCipher cipher, byte[] SBase, byte[] CBase, byte[] vBase, byte[] v, int e,
                                       byte[] aux, byte[] salt, byte[] S, byte[] C, byte[][] seeds, byte[] sample)
    {
        System.arraycopy(S, 0, aux, 0, engine.ffSBytes);
        System.arraycopy(C, 0, aux, engine.ffSBytes, engine.ffCBytes);
        for (int i = 0; i < engine.n1; i++)
        {
            engine.mirathExpandShare(cipher, sample, salt, seeds[engine.mirathTcithPsi(i, e)]);
            // Update base matrices with finite field operations
            byte phi_i = (byte)i;
            engine.mirathMatrixFFMuAddMultipleFF(SBase, phi_i, sample, engine.m, engine.r);
            engine.mirathMatrixFFMuAddMultipleFF(CBase, phi_i, sample, engine.ffSBytes, engine.r, engine.m - engine.r);
            engine.mirathVectorFFMuAddMultiple(vBase, phi_i, sample, engine.ffSBytes + engine.ffCBytes, engine.rho);

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
            engine.mirathExpandShare(cipher, sample, salt, seeds[engine.mirathTcithPsi(i, e)]);
            engine.parseV(sample, v_rnd);

            // Update base matrices with finite field operations
            short phi_i = (short)i;
            engine.mirathMatrixFFMuAddMultipleFF(S_base, phi_i, sample, engine.m, engine.r);
            engine.mirathMatrixFFMuAddMultipleFF(C_base, phi_i, sample, engine.ffSBytes, engine.r, engine.m - engine.r);
            engine.mirathVectorFFMuAddMultiple(v_base, phi_i, v_rnd, engine.rho);

            // Performs S_acc = S_acc + S_rnd, C_acc = C_acc + C_rnd and v[e] = v[e] + v_rnd
            Bytes.xorTo(engine.ffSBytes, sample, aux);
            Bytes.xorTo(engine.ffCBytes, sample, engine.ffSBytes, aux, engine.ffSBytes);
            Shorts.xorTo(engine.rho, v_rnd, v);
        }
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
}
