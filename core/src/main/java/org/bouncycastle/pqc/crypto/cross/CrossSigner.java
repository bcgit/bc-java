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
        byte[][] u_prime = new byte[params.getT()][];
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
        }
        else
        {
            cmt0InputSize = params.getDenselyPackedFpSynSize() +
                params.getDenselyPackedFzRsdpGVecSize() +
                params.getSaltLengthBytes();
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
            }

            // Compute v_bar
            CrossEngine.fzVecSubN(v_bar[i], e_bar, e_bar_prime[i], params);
            CrossEngine.fzDzNormN(v_bar[i]);

            // Convert to FP and compute u_prime
            byte[] v = new byte[params.getN()];
            CrossEngine.convertRestrVecToFp(v, v_bar[i], params);
            u_prime[i] = new byte[params.getN()];
            engine.csprngFpVec(u_prime[i], params);

            // Compute s_prime
            byte[] u = new byte[params.getN()];
            CrossEngine.fpVecByFpVecPointwise(u, v, u_prime[i], params);
            CrossEngine.fpVecByFpMatrix(s_prime, u, V_tr, params);
            CrossEngine.fpDzNormSynd(s_prime, params);

            // Build cmt_0 input
            CrossEngine.packFpSyn(cmt_0_i_input, s_prime, params);
            if (params.rsdp)
            {
                CrossEngine.packFzVec(cmt_0_i_input, v_bar[i], params);
            }
            else
            {
                CrossEngine.packFzRsdpGVec(cmt_0_i_input, v_G_bar[i], params);
            }

            // Compute commitments
            int domain_sep_hash = CrossEngine.HASH_DOMAIN_SEP_CONST + i + (2 * params.getT() - 1);
            CrossEngine.hash(cmt_0[i], cmt_0_i_input, domain_sep_hash, params);

            System.arraycopy(round_seeds, i * params.getSeedLengthBytes(), cmt_1_i_input, 0, params.getSeedLengthBytes());
            CrossEngine.hash(cmt_1, cmt_1_i_input, domain_sep_hash, params);
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
        for (int i = 0; i < params.getT(); i++)
        {
            CrossEngine.fpVecByRestrVecScaled(y[i], e_bar_prime[i], chall_1[i], u_prime[i], params);
            CrossEngine.fpDzNorm(y[i], params);
        }

        // Pack y vectors and compute second challenge
        int packedYSize = params.getT() * params.getDenselyPackedFpVecSize();
        byte[] y_packed = new byte[packedYSize];
        for (int i = 0; i < params.getT(); i++)
        {
            CrossEngine.packFpVec(y_packed, y[i], params);
        }

        byte[] y_digest_chall_1 = new byte[packedYSize + digest_chall_1.length];
        System.arraycopy(y_packed, 0, y_digest_chall_1, 0, packedYSize);
        System.arraycopy(digest_chall_1, 0, y_digest_chall_1, packedYSize, digest_chall_1.length);

        CrossEngine.hash(digest_chall_2, y_digest_chall_1, CrossEngine.HASH_DOMAIN_SEP_CONST, params);

        // Expand to fixed weight challenge
        byte[] chall_2 = new byte[params.getT()];
        engine.expandDigestToFixedWeight(chall_2, digest_chall_2, params);

        // Generate Merkle proofs
        if (params.variant == CrossParameters.FAST)
        {
            proof = new byte[(params.getT() - params.getW()) * params.getHashDigestLength()];
            path = new byte[(params.getT() - params.getW()) * params.getSeedLengthBytes()];
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
            if (chall_2[i] == CrossEngine.TO_PUBLISH)
            {
                if (published_rsps >= params.getT() - params.getW())
                {
                    throw new IllegalStateException("Too many responses to publish");
                }
                CrossEngine.packFpVec(resp_0[published_rsps].y, y[i], params);
                if (params.rsdp)
                {
                    CrossEngine.packFzVec(resp_0[published_rsps].v_bar, v_bar[i], params);
                }
                else
                {
                    CrossEngine.packFzRsdpGVec(resp_0[published_rsps].v_G_bar, v_G_bar[i], params);
                }
                System.arraycopy(cmt_1, i * params.getHashDigestLength(),
                    resp_1[published_rsps], 0, params.getHashDigestLength());
                published_rsps++;
            }
        }
        byte[] sm = new byte[params.getSignatureSize() + message.length];
        //sm = Arrays.concatenate(salt, digest_cmt, digest_chall_2, path, proof, resp_1, resp_1, resp_0)
        int pos = 0;
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
        System.arraycopy(message, 0, sm, pos, message.length);
        return sm;
    }

    public static class Response0
    {
        public byte[] y;
        public byte[] v_bar; // For RSDP
        public byte[] v_G_bar; // For RSDPG
    }


    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return false;
    }
}
