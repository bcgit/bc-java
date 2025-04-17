package org.bouncycastle.pqc.crypto.mirath;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

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
        byte[] sigMsg = new byte[params.getSignatureBytes()];
        byte[] sk = privKey.getEncoded();
        byte[] salt = new byte[engine.saltBytes];
        byte[] rseed = new byte[engine.securityBytes];
        long ctr;
        // Phase 0: Initialization
        byte[][] path = new byte[engine.maxOpen][16];
        byte[] hMpc = new byte[2 * engine.securityBytes];

        byte[] S = new byte[engine.ffSBytes];
        byte[] C = new byte[engine.ffCBytes];
        byte[] H = new byte[engine.ffHBytes];

        byte[] pk = new byte[params.getPublicKeyBytes()];

        byte[][] SBase = new byte[engine.tau][engine.s];
        byte[][] CBase = new byte[engine.tau][engine.c];
        byte[][] vBase = new byte[engine.tau][engine.rho];
        byte[][] v = new byte[engine.tau][engine.rho];
        byte[][] aux = new byte[engine.tau][engine.ffAuxBytes];

        byte[] hSh = new byte[2 * engine.securityBytes]; // or adjust for your hash type

        byte[][] commitsIStar = new byte[engine.tau][2 * engine.securityBytes];
        byte[][] tree = new byte[params.getTreeLeaves() * 2 - 1][engine.securityBytes]; // Assuming an object form


        byte[][] alphaMid = new byte[engine.tau][engine.rho];
        byte[][] alphaBase = new byte[engine.tau][engine.rho];

        // Step 1: Decompress secret key
        engine.mirathMatrixDecompressSecretKey(S, C, H, pk, sk);

        // Steps 2-3: Generate random values
        random.nextBytes(salt);
        random.nextBytes(rseed);

        // Phase 1: Build and Commit Parallel Witness Shares

        byte[][][] commits = new byte[engine.tau][][];
        for (int i = 0; i < engine.tau1; ++i)
        {
            commits[i] = new byte[engine.n1][engine.securityBytes * 2];
        }
        for (int i = engine.tau1; i < engine.tau; ++i)
        {
            commits[i] = new byte[engine.n2][engine.securityBytes * 2];
        }

        // Step 4: Commit to shares
        engine.commitParallelSharings(SBase, CBase, vBase, v, hSh, tree, commits, aux, salt, rseed, S, C);

        // Phase 2: MPC simulation
        byte[] Gamma = new byte[engine.gamma];
        // Step 5: Expand MPC challenge
        engine.mirathTcithExpandMpcChallenge(Gamma, hSh);


        // Steps 6-8: Emulate MPC for each tau
        for (int e = 0; e < engine.tau; e++)
        {
            alphaBase[e] = new byte[engine.rho];
            alphaMid[e] = new byte[engine.rho];
            engine.emulateMPCMu(
                alphaBase[e], alphaMid[e], S, SBase[e],
                C, CBase[e], v[e], vBase[e], Gamma, H
            );
        }

        // Phase 3: Sharing Opening
        // Step 9: Hash MPC results
        engine.mirathTcithHashMpc(hMpc, pk, salt, message, hSh, alphaMid, alphaBase);


        // Step 10: Open random share
        ctr = engine.mirathTcithOpenRandomShare(
            path, commitsIStar, tree, commits, hMpc
        );

        // Step 11: Serialize signature
        engine.unparseSignature(sigMsg, salt, ctr, hMpc, path, commitsIStar, aux, alphaMid);

        return sigMsg;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return false;
    }
}
