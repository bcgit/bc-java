package org.bouncycastle.pqc.crypto.mirath;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Pack;

public class MirathSigner
    implements MessageSigner
{
    private SecureRandom random;
    private MirathParameters params;
    private MirathPublicKeyParameters pubKey;
    private MirathPrivateKeyParameters privKey;

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
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        MirathEngine engine = new MirathEngine(params);
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

        byte[][][] commits = new byte[engine.tau][engine.n1][engine.securityBytes * 2];

        // Phase 1: Build and Commit Parallel Witness Shares
        // Step 1: Decompress secret key
        //engine.mirathMatrixDecompressSecretKey(S, C, H, pk, sk);
        byte[] seedSk = org.bouncycastle.util.Arrays.copyOfRange(sk, 0, engine.securityBytes);
        byte[] seedPk = org.bouncycastle.util.Arrays.copyOfRange(sk, engine.securityBytes, 2 * engine.securityBytes);
        byte[] y = new byte[engine.ffYBytes];

        // Expand matrices from seeds
        engine.mirathMatrixExpandSeedPublicMatrix(H, seedPk);
        engine.mirathMatrixExpandSeedSecretMatrix(S, C, seedSk);

        // Compute y and build public key
        engine.mirathMatrixComputeY(y, S, C, H);
        //unparsePublicKey
        System.arraycopy(seedPk, 0, pk, 0, engine.securityBytes);
        System.arraycopy(y, 0, pk, engine.securityBytes, engine.ffYBytes);
        random.nextBytes(salt);
        random.nextBytes(rseed);
        // Generate commitments
        //hSh is hCom in this stage
        engine.mirathMultivcCommit(seeds, hSh, tree, commits, salt, rseed);

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
            engine.commitParallelSharings(SBase, CBase, vBase, v, hSh, aux, salt, S, C, seeds);

            // Phase 2: MPC simulation
            // Step 5: Expand MPC challenge
            engine.mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 6-8: Emulate MPC for each tau
            for (int e = 0; e < engine.tau; e++)
            {
                alphaBase[e] = new byte[engine.rho];
                alphaMid[e] = new byte[engine.rho];
                engine.emulateMPCMu(alphaBase[e], alphaMid[e], S, SBase[e], C, CBase[e], v[e], vBase[e], Gamma, H);
            }

            // Phase 3: Sharing Opening
            // Step 9: Hash MPC results
            engine.mirathTcithHashMpc(hMpc, pk, salt, message, hSh, alphaMid, alphaBase);

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

            // Step 4: Commit to shares
            engine.commitParallelSharings(SBase, CBase, vBase, v, hSh, aux, salt, S, C, seeds);

            // Phase 2: MPC simulation
            // Step 5: Expand MPC challenge
            engine.mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 6-8: Emulate MPC for each tau
            for (int e = 0; e < engine.tau; e++)
            {
                alphaBase[e] = new short[engine.rho];
                alphaMid[e] = new short[engine.rho];
                engine.emulateMPCMu(alphaBase[e], alphaMid[e], S, SBase[e], C, CBase[e], v[e], vBase[e], Gamma, H);
            }

            // Phase 3: Sharing Opening
            // Step 9: Hash MPC results
            engine.mirathTcithHashMpc(hMpc, pk, salt, message, hSh, alphaMid, alphaBase);

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
        MirathEngine engine = new MirathEngine(params);
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
        // Step 2: Decompress public key
        engine.mirathMatrixDecompressPK(H, y, pk);
        //parseSignature part 1
        int tmpBits = (engine.m * engine.r + engine.r * (engine.m - engine.r) + engine.rho * engine.mu) * engine.tau;
        if (engine.isA)
        {
            tmpBits *= 4;
        }
        int modBits = tmpBits % 8;
        if (modBits != 0)
        {
            int mask = (1 << modBits) - 1;
            int lastByte = signature[engine.signatureBytes - 1] & 0xFF;
            if ((lastByte & ~mask) != 0)
            {
                return false;
            }
        }
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
            int ret = engine.computeParallelShares(SShare, CShare, vShare, iStar, hSh, ctr[0],
                path, commitsIStar, aux, salt, hMpc);
            if (ret != 0)
            {
                return false;
            }

            // Step 4: Expand MPC challenge
            engine.mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 5-6: Emulate parties
            for (int e = 0; e < engine.tau; e++)
            {
                engine.emulatePartyMu(alphaBase[e], iStar[e], SShare[e], CShare[e],
                    vShare[e], Gamma, H, y, alphaMid[e]);
            }

            // Step 7: Compute MPC hash
            engine.mirathTcithHashMpc(hMpcPrime, pk, salt, message, hSh, alphaMid, alphaBase);
        }
        else
        {
            short[][] SShare = new short[engine.tau][engine.s];
            short[][] CShare = new short[engine.tau][engine.c];
            short[][] vShare = new short[engine.tau][engine.rho];
            short[] Gamma = new short[engine.gamma];
            short[][] alphaMid = new short[engine.tau][engine.rho];
            short[][] alphaBase = new short[engine.tau][engine.rho];

            // Step 1: Parse signature
            engine.parseSignature(ptr, aux, alphaMid, signature);

            // Step 3: Compute parallel shares
            int ret = engine.computeParallelShares(SShare, CShare, vShare, iStar, hSh, ctr[0],
                path, commitsIStar, aux, salt, hMpc);
            if (ret != 0)
            {
                return false;
            }

            // Step 4: Expand MPC challenge
            engine.mirathTcithExpandMpcChallenge(Gamma, hSh);

            // Steps 5-6: Emulate parties
            for (int e = 0; e < engine.tau; e++)
            {
                engine.emulatePartyMu(alphaBase[e], iStar[e], SShare[e], CShare[e],
                    vShare[e], Gamma, H, y, alphaMid[e]);
            }

            // Step 7: Compute MPC hash
            engine.mirathTcithHashMpc(hMpcPrime, pk, salt, message, hSh, alphaMid, alphaBase);
        }
        // Step 8: Verify hash equality
        return Arrays.equals(hMpc, hMpcPrime);
    }
}
