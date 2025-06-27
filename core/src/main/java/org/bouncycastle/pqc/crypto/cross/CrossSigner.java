package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

public class CrossSigner
    implements MessageSigner
{
    private CrossEngine engine;
    private CrossParameters params;
    private CrossPublicKeyParameters pubKey;
    private CrossPrivateKeyParameters privKey;
    private SecureRandom random;

    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (CrossPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (CrossPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (CrossPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
        engine = new CrossEngine(params.getSecMarginLambda());
    }

    @Override
    public byte[] generateSignature(byte[] message)//public void sign(SK_t sk, byte[] m, CROSS_sig_t sig)
    {
        byte[] seed_sk = privKey.getEncoded();
        int m = params.getM();
        int w = params.getW();
        int t = params.getT();
        byte[] salt = new byte[params.getSaltLengthBytes()];
        byte[] digest_cmt = new byte[params.getHashDigestLength()];
        byte[] digest_chall_2 = new byte[params.getHashDigestLength()];
        byte[] proof;
        byte[] path;
        Response0[] resp_0 = new Response0[t - w];
        if (params.rsdp)
        {
            for (int i = 0; i < resp_0.length; ++i)
            {
                resp_0[i] = new Response0();
                resp_0[i].y = new byte[params.getDenselyPackedFpVecSize()];
                resp_0[i].v_bar = new byte[params.getDenselyPackedFzVecSize()];
            }
        }
        else
        {
            for (int i = 0; i < resp_0.length; ++i)
            {
                resp_0[i] = new Response0();
                resp_0[i].y = new byte[params.getDenselyPackedFpVecSize()];
                resp_0[i].v_G_bar = new byte[params.getDenselyPackedFzRsdpGVecSize()];
            }
        }
        byte[][] resp_1 = new byte[t - w][params.getHashDigestLength()];

        // Key material expansion
        byte[][] V_tr = new byte[params.getK()][params.getN() - params.getK()];
        byte[] e_bar = new byte[params.getN()];
        byte[] e_G_bar = null;
        byte[][] W_mat = null;

        if (params.rsdp)
        {
            engine.expandSk(params, seed_sk, e_bar, null, V_tr, null);
        }
        else
        {
            e_G_bar = new byte[params.getM()];
            W_mat = new byte[params.getM()][params.getN() - params.getM()];
            engine.expandSk(params, seed_sk, e_bar, e_G_bar, V_tr, W_mat);
        }

        // Generate root seed and salt
        byte[] root_seed = new byte[params.getSeedLengthBytes()];
        random.nextBytes(root_seed);
        random.nextBytes(salt);

        // Generate round seeds
        byte[] round_seeds = new byte[params.getT() * params.getSeedLengthBytes()];
        byte[] seed_tree = null;

        if (params.variant == CrossParameters.FAST)
        {
            engine.seedLeavesSpeed(params, round_seeds, root_seed, salt);
        }
        else
        {
            seed_tree = new byte[params.getNumNodesSeedTree() * params.getSeedLengthBytes()];
            engine.genSeedTree(params, seed_tree, root_seed, salt);
            CrossEngine.seedLeavesTree(params, round_seeds, seed_tree);
        }

        // Prepare arrays for T rounds
        byte[][] e_bar_prime = new byte[params.getT()][];
        byte[][] v_bar = new byte[params.getT()][];
        Object u_prime;
        byte[] s_prime = new byte[params.getN() - params.getK()];
        byte[][] e_G_bar_prime = null;
        byte[][] v_G_bar = null;

        // Prepare commitment inputs
        int cmt0InputSize;
        if (params.rsdp)
        {
            cmt0InputSize = params.getDenselyPackedFpSynSize() +
                params.getDenselyPackedFzVecSize() +
                params.getSaltLengthBytes();
            u_prime = new byte[params.getT()][];
        }
        else
        {
            cmt0InputSize = params.getDenselyPackedFpSynSize() +
                params.getDenselyPackedFzRsdpGVecSize() +
                params.getSaltLengthBytes();
            u_prime = new short[params.getT()][];
            e_G_bar_prime = new byte[params.getT()][];
            v_G_bar = new byte[params.getT()][];
        }

        byte[] cmt_0_i_input = new byte[cmt0InputSize];
        int saltOffset = cmt0InputSize - params.getSaltLengthBytes();
        System.arraycopy(salt, 0, cmt_0_i_input, saltOffset, params.getSaltLengthBytes());

        byte[] cmt_1_i_input = new byte[params.getSeedLengthBytes() + params.getSaltLengthBytes()];
        System.arraycopy(salt, 0, cmt_1_i_input, params.getSeedLengthBytes(), params.getSaltLengthBytes());

        byte[][] cmt_0 = new byte[params.getT()][params.getHashDigestLength()];
        byte[] cmt_1 = new byte[params.getT() * params.getHashDigestLength()];

        // Process each round
        for (int i = 0; i < params.getT(); i++)
        {
            // Prepare CSPRNG input
            byte[] csprng_input = new byte[params.getSeedLengthBytes() + params.getSaltLengthBytes()];
            System.arraycopy(round_seeds, i * params.getSeedLengthBytes(), csprng_input, 0, params.getSeedLengthBytes());
            System.arraycopy(salt, 0, csprng_input, params.getSeedLengthBytes(), params.getSaltLengthBytes());

            int domain_sep_csprng = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + i + (2 * params.getT() - 1);
            engine.init(csprng_input, csprng_input.length, domain_sep_csprng);

            // Expand e_bar_prime
            e_bar_prime[i] = new byte[params.getN()];
            v_bar[i] = new byte[params.getN()];

            if (params.rsdp)
            {
                engine.csprngFzVec(e_bar_prime[i], params);
                // Compute v_bar
                CrossEngine.fzVecSubN(v_bar[i], e_bar, e_bar_prime[i], params);
                byte[] v = new byte[params.getN()];
                CrossEngine.convertRestrVecToFp(v, v_bar[i], params);
                CrossEngine.fzDzNormN(v_bar[i]);

                // Convert to FP and compute u_prime

                ((byte[][])u_prime)[i] = new byte[params.getN()];
                engine.csprngFpVec(((byte[][])u_prime)[i], params);

                // Compute s_prime
                byte[] u = new byte[params.getN()];
                CrossEngine.fpVecByFpVecPointwise(u, v, ((byte[][])u_prime)[i], params);
                CrossEngine.fpVecByFpMatrix(s_prime, u, V_tr, params);
                CrossEngine.fpDzNormSynd(s_prime);

                // Build cmt_0 input
                CrossEngine.packFpSyn(cmt_0_i_input, s_prime);
                CrossEngine.packFzVec(cmt_0_i_input, params.getDenselyPackedFpSynSize(), v_bar[i], params);
            }
            else
            {
                e_G_bar_prime[i] = new byte[params.getM()];
                v_G_bar[i] = new byte[params.getM()];
                engine.csprngFzInfW(e_G_bar_prime[i], params);
                CrossEngine.fzVecSubM(v_G_bar[i], e_G_bar, e_G_bar_prime[i], m);
                CrossEngine.fzDzNormM(v_G_bar[i], m);
                CrossEngine.fzInfWByFzMatrix(e_bar_prime[i], e_G_bar_prime[i], W_mat, params);
                CrossEngine.fzDzNormN(e_bar_prime[i]);
                // Compute v_bar
                CrossEngine.fzVecSubN(v_bar[i], e_bar, e_bar_prime[i], params);
                short[] v = new short[params.getN()];
                CrossEngine.convertRestrVecToFp(v, v_bar[i], params);
                CrossEngine.fzDzNormN(v_bar[i]);

                // Convert to FP and compute u_prime

                ((short[][])u_prime)[i] = new short[params.getN()];
                engine.csprngFpVec(((short[][])u_prime)[i], params);

                // Compute s_prime
                byte[] u = new byte[params.getN()];
                CrossEngine.fpVecByFpVecPointwise(u, v, ((short[][])u_prime)[i], params);
                CrossEngine.fpVecByFpMatrix(s_prime, u, V_tr, params);
                CrossEngine.fpDzNormSynd(s_prime);

                // Build cmt_0 input
                CrossEngine.packFpSyn(cmt_0_i_input, s_prime);
                CrossEngine.packFzRsdpGVec(cmt_0_i_input, params.getDenselyPackedFpSynSize(), v_G_bar[i], params);
            }


            // Compute commitments
            int domain_sep_hash = CrossEngine.HASH_DOMAIN_SEP_CONST + i + (2 * params.getT() - 1);
            CrossEngine.hash(cmt_0[i], cmt_0_i_input, domain_sep_hash, params);

            System.arraycopy(round_seeds, i * params.getSeedLengthBytes(), cmt_1_i_input, 0, params.getSeedLengthBytes());
            CrossEngine.hash(cmt_1, i * params.getHashDigestLength(), cmt_1_i_input, domain_sep_hash, params);
        }

        // Compute root digests
        byte[] digest_cmt0_cmt1 = new byte[2 * params.getHashDigestLength()];
        byte[] merkle_tree_0 = null;
        if (params.variant == CrossParameters.FAST)
        {
            engine.treeRootSpeed(digest_cmt0_cmt1, cmt_0, params);
        }
        else
        {
            merkle_tree_0 = new byte[params.getNumNodesMerkleTree() * params.getHashDigestLength()];
            engine.treeRootBalanced(digest_cmt0_cmt1, merkle_tree_0, cmt_0, params);
        }

        byte[] cmt1_hash = new byte[params.getHashDigestLength()];
        CrossEngine.hash(cmt1_hash, cmt_1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
        System.arraycopy(cmt1_hash, 0, digest_cmt0_cmt1, params.getHashDigestLength(), params.getHashDigestLength());

        CrossEngine.hash(digest_cmt, digest_cmt0_cmt1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        // First challenge extraction
        byte[] digest_msg = new byte[params.getHashDigestLength()];
        CrossEngine.hash(digest_msg, message, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        byte[] digest_msg_cmt_salt = new byte[2 * params.getHashDigestLength() + params.getSaltLengthBytes()];
        System.arraycopy(digest_msg, 0, digest_msg_cmt_salt, 0, params.getHashDigestLength());
        System.arraycopy(digest_cmt, 0, digest_msg_cmt_salt, params.getHashDigestLength(), params.getHashDigestLength());
        System.arraycopy(salt, 0, digest_msg_cmt_salt, 2 * params.getHashDigestLength(), params.getSaltLengthBytes());

        byte[] digest_chall_1 = new byte[params.getHashDigestLength()];
        CrossEngine.hash(digest_chall_1, digest_msg_cmt_salt, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        // Expand first challenge
        int dsc_csprng_chall_1 = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + (3 * params.getT() - 1);
        engine.init(digest_chall_1, digest_chall_1.length, dsc_csprng_chall_1);
        int[] chall_1 = engine.csprngFpVecChall1(params);

        // Compute first round responses
        byte[][] y = new byte[params.getT()][params.getN()];
        if (params.rsdp)
        {
            for (int i = 0; i < params.getT(); i++)
            {
                CrossEngine.fpVecByRestrVecScaled(y[i], e_bar_prime[i], chall_1[i], ((byte[][])u_prime)[i], params);
                CrossEngine.fpDzNorm(y[i], params);
            }
        }
        else
        {
            for (int i = 0; i < params.getT(); i++)
            {
                CrossEngine.fpVecByRestrVecScaled(y[i], e_bar_prime[i], chall_1[i], ((short[][])u_prime)[i], params);
                CrossEngine.fpDzNorm(y[i], params);
            }
        }

        // Pack y vectors and compute second challenge
        int packedYSize = params.getT() * params.getDenselyPackedFpVecSize();
        byte[] y_digest_chall_1 = new byte[packedYSize + digest_chall_1.length];
        for (int i = 0; i < params.getT(); i++)
        {
            CrossEngine.packFpVec(y_digest_chall_1, i * params.getDenselyPackedFpVecSize(), y[i], params);
        }

        System.arraycopy(digest_chall_1, 0, y_digest_chall_1, packedYSize, digest_chall_1.length);

        CrossEngine.hash(digest_chall_2, y_digest_chall_1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        // Expand to fixed weight challenge
        byte[] chall_2 = new byte[params.getT()];
        engine.expandDigestToFixedWeight(chall_2, digest_chall_2, params);

        // Generate Merkle proofs
        if (params.variant == CrossParameters.FAST)
        {
            proof = new byte[params.getW() * params.getHashDigestLength()];
            path = new byte[params.getW() * params.getSeedLengthBytes()];
            CrossEngine.treeProofSpeed(proof, cmt_0, chall_2, params.getHashDigestLength());
            CrossEngine.seedPathSpeed(path, round_seeds, chall_2, params.getSeedLengthBytes());
        }
        else
        {
            proof = new byte[params.getHashDigestLength() * params.getTreeNodesToStore()];
            path = new byte[params.getTreeNodesToStore() * params.getSeedLengthBytes()];
            CrossEngine.treeProofBalanced(proof, merkle_tree_0, chall_2, params);
            CrossEngine.seedPathBalanced(path, seed_tree, chall_2, params);
        }

        // Collect responses
        int published_rsps = 0;
        for (int i = 0; i < params.getT(); i++)
        {
            if (chall_2[i] == 0)
            {
                if (published_rsps >= params.getT() - params.getW())
                {
                    throw new IllegalStateException("Too many responses to publish");
                }
                CrossEngine.packFpVec(resp_0[published_rsps].y, y[i], params);
                if (params.rsdp)
                {
                    CrossEngine.packFzVec(resp_0[published_rsps].v_bar, 0, v_bar[i], params);
                }
                else
                {
                    CrossEngine.packFzRsdpGVec(resp_0[published_rsps].v_G_bar, 0, v_G_bar[i], params);
                }
                System.arraycopy(cmt_1, i * params.getHashDigestLength(),
                    resp_1[published_rsps], 0, params.getHashDigestLength());
                published_rsps++;
            }
        }
        byte[] sm = new byte[params.getSignatureSize() + message.length];
        int pos = 0;
        System.arraycopy(message, 0, sm, pos, message.length);
        pos += message.length;
        //sm = Arrays.concatenate(salt, digest_cmt, digest_chall_2, path, proof, resp_1, resp_1, resp_0)

        System.arraycopy(salt, 0, sm, pos, salt.length);
        pos += salt.length;
        System.arraycopy(digest_cmt, 0, sm, pos, digest_cmt.length);
        pos += digest_cmt.length;
        System.arraycopy(digest_chall_2, 0, sm, pos, digest_chall_2.length);
        pos += digest_chall_2.length;
        System.arraycopy(path, 0, sm, pos, path.length);
        pos += path.length;
        System.arraycopy(proof, 0, sm, pos, proof.length);
        pos += proof.length;
        for (int i = 0; i < resp_1.length; ++i)
        {
            System.arraycopy(resp_1[i], 0, sm, pos, resp_1[i].length);
            pos += resp_1[i].length;
        }
        if (params.rsdp)
        {
            for (int i = 0; i < resp_0.length; ++i)
            {
                System.arraycopy(resp_0[i].y, 0, sm, pos, resp_0[i].y.length);
                pos += resp_0[i].y.length;
                System.arraycopy(resp_0[i].v_bar, 0, sm, pos, resp_0[i].v_bar.length);
                pos += resp_0[i].v_bar.length;
            }
        }
        else
        {
            for (int i = 0; i < resp_1.length; ++i)
            {
                System.arraycopy(resp_0[i].y, 0, sm, pos, resp_0[i].y.length);
                pos += resp_0[i].y.length;
                System.arraycopy(resp_0[i].v_G_bar, 0, sm, pos, resp_0[i].v_G_bar.length);
                pos += resp_0[i].v_G_bar.length;
            }
        }

        return sm;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        int t = params.getT();
        int K = params.getK();
        int N = params.getN();
        int M = params.getM();
        int w = params.getW();
        int hashDigestLength = params.getHashDigestLength();
        int saltLength = params.getSaltLengthBytes();
        int seedLength = params.getSeedLengthBytes();

        // Expand public key based on variant
        Object V_tr = null;
        byte[][] W_mat = null;
        byte[] publicKey = pubKey.getEncoded();
        byte[] seedSk = Arrays.copyOf(publicKey, params.getKeypairSeedLengthBytes());
        int pos = message.length;
        byte[] path, proof;
        if (params.variant == CrossParameters.FAST)
        {
            proof = new byte[w * params.getHashDigestLength()];
            path = new byte[w * params.getSeedLengthBytes()];
        }
        else
        {
            proof = new byte[params.getHashDigestLength() * params.getTreeNodesToStore()];
            path = new byte[params.getTreeNodesToStore() * params.getSeedLengthBytes()];
        }

        // Fixed-length components
        byte[] salt = extract(signature, pos, params.getSaltLengthBytes());
        pos += params.getSaltLengthBytes();

        byte[] digest_cmt = extract(signature, pos, params.getHashDigestLength());
        pos += params.getHashDigestLength();

        byte[] digestChall2 = extract(signature, pos, params.getHashDigestLength());
        pos += params.getHashDigestLength();

        path = extract(signature, pos, path.length);
        pos += path.length;

        proof = extract(signature, pos, proof.length);
        pos += proof.length;

        // resp_1: T elements of hash digest length
        byte[][] resp_1 = new byte[t - w][];
        for (int i = 0; i < resp_1.length; i++)
        {
            resp_1[i] = extract(signature, pos, params.getHashDigestLength());
            pos += params.getHashDigestLength();
        }

        // resp_0: Variable number of elements (tau) based on remaining bytes
        int blockSize = params.rsdp
            ? params.getDenselyPackedFpVecSize() + params.getDenselyPackedFzVecSize()
            : params.getDenselyPackedFpVecSize() + params.getDenselyPackedFzRsdpGVecSize();

        int remainingBytes = signature.length - pos;
        if (remainingBytes % blockSize != 0)
        {
            throw new IllegalArgumentException("Invalid signature length");
        }

        int tau = remainingBytes / blockSize;
        Response0[] resp0 = new Response0[tau];

        for (int i = 0; i < tau; i++)
        {
            Response0 resp = new Response0();
            resp.y = extract(signature, pos, params.getDenselyPackedFpVecSize());
            pos += params.getDenselyPackedFpVecSize();

            if (params.rsdp)
            {
                resp.v_bar = extract(signature, pos, params.getDenselyPackedFzVecSize());
                pos += params.getDenselyPackedFzVecSize();
            }
            else
            {
                resp.v_G_bar = extract(signature, pos, params.getDenselyPackedFzRsdpGVecSize());
                pos += params.getDenselyPackedFzRsdpGVecSize();
            }
            resp0[i] = resp;
        }

        if (params.rsdp)
        {
            byte[][] vTr = new byte[K][N - K];
            engine.expandPk(params, vTr, seedSk);
            V_tr = vTr;
        }
        else
        {
            short[][] vTr = new short[K][N - K];
            W_mat = new byte[M][N - M];
            engine.expandPk(params, vTr, W_mat, seedSk);
            V_tr = vTr;
        }

        // Unpack syndrome
        byte[] s = new byte[N - K];
        boolean isPaddKeyOk = CrossEngine.unpackFpSyn(s, Arrays.copyOfRange(publicKey, seedSk.length, publicKey.length), params);

        // Compute digest_msg_cmt_salt
        byte[] digestMsgCmtSalt = new byte[2 * hashDigestLength + saltLength];
        byte[] tempHash = new byte[hashDigestLength];
        CrossEngine.hash(tempHash, message, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
        System.arraycopy(tempHash, 0, digestMsgCmtSalt, 0, hashDigestLength);
        System.arraycopy(digest_cmt, 0, digestMsgCmtSalt, hashDigestLength, hashDigestLength);
        System.arraycopy(salt, 0, digestMsgCmtSalt, 2 * hashDigestLength, saltLength);

        // Compute digest_chall_1
        byte[] digestChall1 = new byte[hashDigestLength];
        CrossEngine.hash(digestChall1, digestMsgCmtSalt, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
        engine.init(digestChall1, digestChall1.length, CrossEngine.CSPRNG_DOMAIN_SEP_CONST + (3 * t - 1));
        // Generate challenge 1 vector
        int[] chall1 = engine.csprngFpVecChall1(params);

        // Expand challenge 2 to fixed weight
        byte[] chall2 = new byte[t];
        engine.expandDigestToFixedWeight(chall2, digestChall2, params);

        // Rebuild seed tree
        byte[] roundSeeds = new byte[t * seedLength];
        boolean isStreePaddingOk;
        if (params.variant == CrossParameters.FAST)
        {
            isStreePaddingOk = CrossEngine.rebuildLeaves(roundSeeds, chall2, path, seedLength);
        }
        else
        {
            int numNodes = params.getNumNodesSeedTree();
            byte[] seedTree = new byte[numNodes * seedLength];
            isStreePaddingOk = engine.rebuildTree(seedTree, chall2, path, salt, params);
            CrossEngine.seedLeavesTree(params, roundSeeds, seedTree);
        }

        // Prepare buffers for commitments
        int packedFpSynSize = params.getDenselyPackedFpSynSize();
        int packedFzVecSize = params.getDenselyPackedFzVecSize();
        int packedFzRsdpGVecSize = params.getDenselyPackedFzRsdpGVecSize();
        int cmt0InputSize = packedFpSynSize + (params.rsdp ? packedFzVecSize : packedFzRsdpGVecSize) + saltLength;
        int saltOffset = cmt0InputSize - saltLength;

        byte[] cmt0_i_input = new byte[cmt0InputSize];
        System.arraycopy(salt, 0, cmt0_i_input, saltOffset, saltLength);

        byte[] cmt1_i_input = new byte[seedLength + saltLength];
        System.arraycopy(salt, 0, cmt1_i_input, seedLength, saltLength);

        byte[][] cmt0 = new byte[t][hashDigestLength];
        byte[] cmt1 = new byte[t * hashDigestLength];

        byte[] e_bar_prime = new byte[N];
        byte[] u_prime = new byte[N];
        byte[] y_prime = new byte[N];
        byte[] y_prime_H = new byte[N - K];
        byte[] s_prime = new byte[N - K];

        byte[][] y = new byte[t][N];
        int usedRsps = 0;
        boolean isSignatureOk = true;
        boolean isPackedPaddOk = true;

        for (int i = 0; i < t; i++)
        {
            int domainSepCsprng = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + i + (2 * t - 1);
            int domainSepHash = CrossEngine.HASH_DOMAIN_SEP_CONST + i + (2 * t - 1);

            if (chall2[i] == 1)
            {
                // Round with challenge=1
                System.arraycopy(roundSeeds, i * seedLength, cmt1_i_input, 0, seedLength);
                CrossEngine.hash(cmt1, i * hashDigestLength, cmt1_i_input, domainSepHash, params);

                byte[] csprngInput = new byte[seedLength + saltLength];
                System.arraycopy(roundSeeds, i * seedLength, csprngInput, 0, seedLength);
                System.arraycopy(salt, 0, csprngInput, seedLength, saltLength);

                engine.init(csprngInput, csprngInput.length, domainSepCsprng);
                if (params.rsdp)
                {
                    engine.csprngFzVec(e_bar_prime, params);
                }
                else
                {
                    byte[] e_G_bar_prime = new byte[M];
                    engine.csprngFzInfW(e_G_bar_prime, params);
                    CrossEngine.fzInfWByFzMatrix(e_bar_prime, e_G_bar_prime, W_mat, params);
                    CrossEngine.fzDzNormN(e_bar_prime);
                }

                engine.csprngFpVec(u_prime, params);
                CrossEngine.fpVecByRestrVecScaled(y[i], e_bar_prime, chall1[i], u_prime, params);
                CrossEngine.fpDzNorm(y[i], params);
            }
            else
            {
                // Round with challenge=0
                byte[] resp1 = resp_1[usedRsps];

                isPackedPaddOk &= CrossEngine.unpackFpVec(y[i], resp0[usedRsps].y, params);
                System.arraycopy(resp1, 0, cmt1, i * hashDigestLength, hashDigestLength);

                if (params.rsdp)
                {
                    byte[] v_bar = new byte[N];
                    isPackedPaddOk &= CrossEngine.unpackFzVec(v_bar, resp0[usedRsps].v_bar, params);
                    System.arraycopy(resp0[usedRsps].v_bar, 0, cmt0_i_input, packedFpSynSize, packedFzVecSize);
                    isSignatureOk &= CrossEngine.isFzVecInRestrGroupN(v_bar, params);

                    byte[] v = new byte[N];
                    CrossEngine.convertRestrVecToFp(v, v_bar, params);
                    CrossEngine.fpVecByFpVecPointwise(y_prime, v, y[i], params);
                    CrossEngine.fpVecByFpMatrix(y_prime_H, y_prime, (byte[][])V_tr, params);
                    CrossEngine.fpDzNormSynd(y_prime_H);
                    CrossEngine.fpSyndMinusFpVecScaled(s_prime, y_prime_H, (byte)chall1[i], s, params);
                    CrossEngine.fpDzNormSynd(s_prime);

                    CrossEngine.packFpSyn(cmt0_i_input, s_prime);
                }
                else
                {
                    byte[] v_G_bar = new byte[M];
                    isPackedPaddOk &= CrossEngine.unpackFzRsdpGVec(v_G_bar, resp0[usedRsps].v_G_bar, params);
                    isSignatureOk &= CrossEngine.isFzVecInRestrGroupM(v_G_bar, params.getZ(), params.getM());

                    byte[] v_bar = new byte[N];
                    CrossEngine.fzInfWByFzMatrix(v_bar, v_G_bar, W_mat, params);
                    byte[] v = new byte[N];
                    CrossEngine.convertRestrVecToFp(v, v_bar, params);
                    CrossEngine.fpVecByFpVecPointwise(y_prime, v, y[i], params);
                    //TODO: (short[][])
                    CrossEngine.fpVecByFpMatrix(y_prime_H, y_prime, (byte[][])V_tr, params);
                    CrossEngine.fpDzNormSynd(y_prime_H);
                    //TODO: short?
                    CrossEngine.fpSyndMinusFpVecScaled(s_prime, y_prime_H, (byte)chall1[i], s, params);
                    CrossEngine.fpDzNormSynd(s_prime);

                    CrossEngine.packFpSyn(cmt0_i_input, s_prime);
                    System.arraycopy(resp0[usedRsps].v_G_bar, 0, cmt0_i_input, packedFpSynSize, packedFzRsdpGVecSize);
                }

                CrossEngine.hash(cmt0[i], 0, cmt0_i_input, domainSepHash, params);
                usedRsps++;
            }
        }

        // Recompute Merkle root
        byte[] digestCmt0Cmt1 = new byte[2 * hashDigestLength];
        boolean isMtreePaddingOk;
        if (params.variant == CrossParameters.FAST)
        {
            isMtreePaddingOk = engine.recomputeRootSpeed(digestCmt0Cmt1, cmt0, proof, chall2, params);
        }
        else
        {
            isMtreePaddingOk = CrossEngine.recomputeRootTreeBased(digestCmt0Cmt1, cmt0, proof, chall2, params);
        }


        byte[] cmt1Hash = new byte[hashDigestLength];
        CrossEngine.hash(cmt1Hash, cmt1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
        System.arraycopy(cmt1Hash, 0, digestCmt0Cmt1, hashDigestLength, hashDigestLength);

        byte[] digestCmtPrime = new byte[hashDigestLength];
        CrossEngine.hash(digestCmtPrime, digestCmt0Cmt1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        // Compute challenge 2 prime
        int packedFpVecSize = params.getDenselyPackedFpVecSize();
        byte[] yDigestChall1 = new byte[t * packedFpVecSize + hashDigestLength];
        for (int i = 0; i < t; i++)
        {
            byte[] packedY = new byte[packedFpVecSize];
            CrossEngine.packFpVec(packedY, y[i], params);
            System.arraycopy(packedY, 0, yDigestChall1, i * packedFpVecSize, packedFpVecSize);
        }
        System.arraycopy(digestChall1, 0, yDigestChall1, t * packedFpVecSize, hashDigestLength);

        byte[] digestChall2Prime = new byte[hashDigestLength];
        CrossEngine.hash(digestChall2Prime, yDigestChall1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        // Final checks
        boolean doesDigestCmtMatch = Arrays.constantTimeAreEqual(digestCmtPrime, digest_cmt);
        boolean doesDigestChall2Match = Arrays.constantTimeAreEqual(digestChall2Prime, digestChall2);

        isSignatureOk = isSignatureOk && doesDigestCmtMatch && doesDigestChall2Match &&
            isMtreePaddingOk && isStreePaddingOk && isPaddKeyOk && isPackedPaddOk;

        return isSignatureOk;
    }

    private byte[] extract(byte[] source, int start, int length)
    {
        byte[] result = new byte[length];
        System.arraycopy(source, start, result, 0, length);
        return result;
    }

    private static class Response0
    {
        public byte[] y;
        public byte[] v_bar; // For RSDP
        public byte[] v_G_bar; // For RSDPG
    }
}
