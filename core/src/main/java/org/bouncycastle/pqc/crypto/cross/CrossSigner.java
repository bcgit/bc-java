package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

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
        engine = new CrossEngine(params);
    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        byte[] seed_sk = privKey.getEncoded();
        int m = params.getM();
        int w = params.getW();
        int t = params.getT();
        int k = params.getK();
        int n = params.getN();
        int z = params.getZ();
        int hashDigestLength = params.getHashDigestLength();
        byte[] sm = new byte[params.getSignatureSize() + message.length];
        int pos = 0;
        byte[] salt = new byte[hashDigestLength]; //digest_chall_1
        // Key material expansion
        Object V_tr;
        byte[] e_bar = new byte[n];
        byte[] e_G_bar = null;
        byte[][] W_mat = null;
        // Prepare arrays for T rounds
        byte[][] e_bar_prime = new byte[t][n];
        byte[][] v_bar = new byte[t][n];
        Object u_prime;
        Object s_prime;
        byte[][] e_G_bar_prime = null;
        byte[][] v_G_bar = null;
        // Generate root seed and salt
        byte[] root_seed = new byte[params.getSeedLengthBytes()];
        // Generate round seeds
        byte[] round_seeds = new byte[t * params.getSeedLengthBytes()];
        byte[] seed_tree = null;

        int keypairSeedLen = params.getKeypairSeedLengthBytes();
        byte[][] seedESeedPk = new byte[2][keypairSeedLen];
        // Prepare commitment inputs
        int cmt0InputSize = params.getDenselyPackedFpSynSize();
        byte[][] cmt_0 = new byte[t][hashDigestLength];
        byte[] cmt_1 = new byte[t * hashDigestLength];
        // Compute root digests
        byte[] digest_cmt0_cmt1 = new byte[2 * hashDigestLength];
        byte[] merkle_tree_0 = null;
        byte[] chall_2 = new byte[t];
        Object y;
        byte[] y_digest_chall_1 = new byte[t * params.getDenselyPackedFpVecSize()];

        System.arraycopy(message, 0, sm, pos, message.length);
        pos += message.length;
        random.nextBytes(root_seed);
        random.nextBytes(salt);
        System.arraycopy(salt, 0, sm, pos, salt.length);
        pos += salt.length;
        if (params.variant == CrossParameters.FAST)
        {
            engine.seedLeavesSpeed(params, round_seeds, root_seed, salt);
        }
        else
        {
            seed_tree = new byte[params.getNumNodesSeedTree() * params.getSeedLengthBytes()];
            merkle_tree_0 = new byte[params.getNumNodesMerkleTree() * hashDigestLength];
            engine.genSeedTree(params, seed_tree, root_seed, salt);
            CrossEngine.seedLeavesTree(params, round_seeds, seed_tree);
        }
        // Step 1: Initialize CSPRNG for secret key expansion
        engine.init(seed_sk, seed_sk.length, 3 * params.getT() + 1);

        // Step 2: Generate seeds for error vector and public key
        engine.randomBytes(seedESeedPk[0], keypairSeedLen);
        engine.randomBytes(seedESeedPk[1], keypairSeedLen);
        if (params.rsdp)
        {
            V_tr = new byte[k][n - k];
            engine.expandSk(params, seedESeedPk, e_bar, (byte[][])V_tr);
            cmt0InputSize += params.getDenselyPackedFzVecSize();
            u_prime = new byte[t][n];
            s_prime = new byte[n - k];
        }
        else
        {
            V_tr = new short[k][n - k];
            e_G_bar = new byte[m];
            W_mat = new byte[m][n - m];
            engine.expandSk(params, seedESeedPk, e_bar, e_G_bar, (short[][])V_tr, W_mat);
            cmt0InputSize += params.getDenselyPackedFzRsdpGVecSize();
            u_prime = new short[t][n];
            e_G_bar_prime = new byte[t][m];
            v_G_bar = new byte[t][m];
            s_prime = new short[n - k];
        }

        byte[] cmt0_i_input = new byte[cmt0InputSize];

        // Process each round
        for (int i = 0, domain_sep_hash = CrossEngine.HASH_DOMAIN_SEP_CONST + (2 * t - 1); i < t; i++, domain_sep_hash++)
        {
            // Prepare CSPRNG input
            int domain_sep_csprng = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + i + (2 * t - 1);
            engine.init(round_seeds, i * params.getSeedLengthBytes(), params.getSeedLengthBytes(), salt, domain_sep_csprng);

            if (params.rsdp)
            {
                engine.csprngFVec(e_bar_prime[i], z, n, Utils.roundUp(params.getBitsNFzCtRng(), 8) >>> 3);
                // Compute v_bar
                CrossEngine.fzVecSub(v_bar[i], e_bar, e_bar_prime[i], n);
                byte[] v = new byte[n];
                CrossEngine.convertRestrVecToFp(v, v_bar[i], params);
                CrossEngine.fDzNorm(v_bar[i], v_bar[i].length);

                // Convert to FP and compute u_prime
                engine.csprngFVec(((byte[][])u_prime)[i], params.getP(), n, Utils.roundUp(params.getBitsNFpCtRng(), 8) >>> 3);

                // Compute s_prime
                byte[] u = new byte[n];
                CrossEngine.fpVecByFpVecPointwise(u, v, ((byte[][])u_prime)[i], params);
                CrossEngine.fpVecByFpMatrix((byte[])s_prime, u, (byte[][])V_tr, params);
                CrossEngine.fDzNorm((byte[])s_prime, ((byte[])s_prime).length);

                // Build cmt_0 input
                Utils.genericPack7Bit(cmt0_i_input, 0, (byte[])s_prime, ((byte[])s_prime).length);
                Utils.genericPack3Bit(cmt0_i_input, params.getDenselyPackedFpSynSize(), v_bar[i], n);
            }
            else
            {
                engine.csprngFVec(e_G_bar_prime[i], z, m, Utils.roundUp(params.getBitsMFzCtRng(), 8) >>> 3);
                CrossEngine.fzVecSub(v_G_bar[i], e_G_bar, e_G_bar_prime[i], m);
                CrossEngine.fDzNorm(v_G_bar[i], m);
                CrossEngine.fzInfWByFzMatrix(e_bar_prime[i], e_G_bar_prime[i], W_mat, params);
                CrossEngine.fDzNorm(e_bar_prime[i], e_bar_prime[i].length);
                // Compute v_bar
                CrossEngine.fzVecSub(v_bar[i], e_bar, e_bar_prime[i], n);
                short[] v = new short[n];
                CrossEngine.convertRestrVecToFp(v, v_bar[i], params);
                CrossEngine.fDzNorm(v_bar[i], v_bar[i].length);

                // Convert to FP and compute u_prime
                engine.csprngFpVec(((short[][])u_prime)[i], params);

                // Compute s_prime
                short[] u = new short[n];
                CrossEngine.fpVecByFpVecPointwise(u, v, ((short[][])u_prime)[i], params);
                CrossEngine.fpVecByFpMatrix((short[])s_prime, u, (short[][])V_tr, params);

                // Build cmt_0 input
                Utils.genericPack9Bit(cmt0_i_input, 0, (short[])s_prime);
                Utils.genericPack7Bit(cmt0_i_input, params.getDenselyPackedFpSynSize(), v_G_bar[i], m);
            }

            // Compute commitments

            byte[] domain_sep_hash_bytes = Pack.shortToLittleEndian((short)domain_sep_hash);
            engine.hash(cmt_0[i], 0, cmt0_i_input, 0, cmt0_i_input.length, salt, 0, salt.length, domain_sep_hash_bytes);
            engine.hash(cmt_1, i * hashDigestLength, round_seeds, i * params.getSeedLengthBytes(), params.getSeedLengthBytes(),
                salt, 0, hashDigestLength, domain_sep_hash_bytes);
        }

        if (params.variant == CrossParameters.FAST)
        {
            engine.treeRootSpeed(digest_cmt0_cmt1, cmt_0, params);
        }
        else
        {
            engine.treeRootBalanced(digest_cmt0_cmt1, merkle_tree_0, cmt_0, params);
        }

        engine.hash(digest_cmt0_cmt1, hashDigestLength, cmt_1, 0, cmt_1.length, CrossEngine.HASH_DOMAIN_SEP);
        engine.hash(sm, pos, digest_cmt0_cmt1, 0, digest_cmt0_cmt1.length, CrossEngine.HASH_DOMAIN_SEP);

        // First challenge extraction
        engine.hash(salt, 0, message, 0, message.length, CrossEngine.HASH_DOMAIN_SEP);
        // hash(digest_chall_1 || digest_cmt || salt || dsc)
        engine.hash(salt, 0, salt, sm, pos, hashDigestLength, sm, message.length, hashDigestLength, CrossEngine.HASH_DOMAIN_SEP);
        pos += hashDigestLength;
        // Expand first challenge
        int dsc_csprng_chall_1 = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + (3 * t - 1);
        engine.init(salt, salt.length, dsc_csprng_chall_1);
        int[] chall_1 = engine.csprngFpVecChall1(params);

        // Compute first round responses
        if (params.rsdp)
        {
            y = new byte[t][n];
            for (int i = 0; i < t; i++)
            {
                CrossEngine.fpVecByRestrVecScaled(((byte[][])y)[i], e_bar_prime[i], chall_1[i], ((byte[][])u_prime)[i], params);
                CrossEngine.fDzNorm(((byte[][])y)[i], n);
            }
            // Pack y vectors and compute second challenge
            for (int i = 0; i < t; i++)
            {
                Utils.genericPack7Bit(y_digest_chall_1, i * params.getDenselyPackedFpVecSize(), ((byte[][])y)[i], ((byte[][])y)[i].length);
            }
        }
        else
        {
            y = new short[t][n];
            for (int i = 0; i < t; i++)
            {
                CrossEngine.fpVecByRestrVecScaled(((short[][])y)[i], e_bar_prime[i], chall_1[i], ((short[][])u_prime)[i], params);
            }
            // Pack y vectors and compute second challenge
            for (int i = 0; i < t; i++)
            {
                Utils.genericPack9Bit(y_digest_chall_1, i * params.getDenselyPackedFpVecSize(), ((short[][])y)[i]);
            }
        }
        engine.hash(sm, pos, y_digest_chall_1, 0, y_digest_chall_1.length, salt, 0, salt.length, CrossEngine.HASH_DOMAIN_SEP);

        // Expand to fixed weight challenge
        engine.expandDigestToFixedWeight(chall_2, sm, pos, params);
        pos += hashDigestLength;

        // Generate Merkle proofs
        if (params.variant == CrossParameters.FAST)
        {
            CrossEngine.seedPathSpeed(sm, pos, round_seeds, chall_2, params.getSeedLengthBytes());
            pos += w * params.getSeedLengthBytes();
            CrossEngine.treeProofSpeed(sm, pos, cmt_0, chall_2, hashDigestLength);
            pos += w * hashDigestLength;
        }
        else
        {
            CrossEngine.seedPathBalanced(sm, pos, seed_tree, chall_2, params);
            pos += params.getTreeNodesToStore() * params.getSeedLengthBytes();
            CrossEngine.treeProofBalanced(sm, pos, merkle_tree_0, chall_2, params);
            pos += hashDigestLength * params.getTreeNodesToStore();
        }

        // Collect responses
        int published_rsps = 0;
        int pos2 = pos + hashDigestLength * (t - w);
        for (int i = 0; i < t; i++)
        {
            if (chall_2[i] == 0)
            {
                if (published_rsps >= t - w)
                {
                    throw new IllegalStateException("Too many responses to publish");
                }

                if (params.rsdp)
                {
                    Utils.genericPack7Bit(sm, pos2, ((byte[][])y)[i], ((byte[][])y)[i].length);
                    pos2 += params.getDenselyPackedFpVecSize();
                    Utils.genericPack3Bit(sm, pos2, v_bar[i], n);
                    pos2 += params.getDenselyPackedFzVecSize();
                }
                else
                {
                    Utils.genericPack9Bit(sm, pos2, ((short[][])y)[i]);
                    pos2 += params.getDenselyPackedFpVecSize();
                    Utils.genericPack7Bit(sm, pos2, v_G_bar[i], m);
                    pos2 += params.getDenselyPackedFzRsdpGVecSize();
                }
                System.arraycopy(cmt_1, i * hashDigestLength, sm, pos, hashDigestLength);
                published_rsps++;
                pos += hashDigestLength;
            }
        }
        return sm;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        int t = params.getT();
        int k = params.getK();
        int n = params.getN();
        int m = params.getM();
        int w = params.getW();
        int z = params.getZ();
        int hashDigestLength = params.getHashDigestLength();
        int saltLength = params.getHashDigestLength();
        int seedLength = params.getSeedLengthBytes();
        Object y_prime_H;
        // Expand public key based on variant
        Object V_tr;
        Object s;
        byte[][] W_mat = null;
        byte[] publicKey = pubKey.getEncoded();
        byte[] seedSk = Arrays.copyOf(publicKey, params.getKeypairSeedLengthBytes());
        int pos = message.length;
        byte[] path, proof;
        byte[][] cmt0 = new byte[t][hashDigestLength];
        byte[] cmt1 = new byte[t * hashDigestLength];

        byte[] e_bar_prime = new byte[n];
        Object u_prime, y_prime, s_prime, v;
        Object y;
        if (params.rsdp)
        {
            y_prime_H = new byte[n - k];
            V_tr = new byte[k][n - k];
            s = new byte[n - k];
            u_prime = new byte[n];
            y_prime = new byte[n];
            s_prime = new byte[n - k];
            y = new byte[t][n];
            v = new byte[n];
        }
        else
        {
            y_prime_H = new short[n - k];
            V_tr = new short[k][n - k];
            s = new short[n - k];
            u_prime = new short[n];
            y_prime = new short[n];
            s_prime = new short[n - k];
            y = new short[t][n];
            v = new short[n];
            W_mat = new byte[m][n - m];
        }
        if (params.variant == CrossParameters.FAST)
        {
            proof = new byte[w * hashDigestLength];
            path = new byte[w * params.getSeedLengthBytes()];
        }
        else
        {
            proof = new byte[hashDigestLength * params.getTreeNodesToStore()];
            path = new byte[params.getTreeNodesToStore() * params.getSeedLengthBytes()];
        }

        // Fixed-length components
        byte[] salt = extract(signature, pos, saltLength);
        pos += saltLength;

        byte[] digest_cmt = extract(signature, pos, hashDigestLength);
        pos += hashDigestLength;

        byte[] digestChall2 = extract(signature, pos, hashDigestLength);
        pos += hashDigestLength;

        path = extract(signature, pos, path.length);
        pos += path.length;

        proof = extract(signature, pos, proof.length);
        pos += proof.length;

        // resp_1: T elements of hash digest length
        byte[][] resp_1 = new byte[t - w][];
        for (int i = 0; i < resp_1.length; i++)
        {
            resp_1[i] = extract(signature, pos, hashDigestLength);
            pos += hashDigestLength;
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
                resp.v_bar = extract(signature, pos, params.getDenselyPackedFzRsdpGVecSize());
                pos += params.getDenselyPackedFzRsdpGVecSize();
            }
            resp0[i] = resp;
        }

        boolean isPaddKeyOk;
        if (params.rsdp)
        {
            engine.expandPk(params, (byte[][])V_tr, seedSk);
            // Unpack syndrome
            isPaddKeyOk = Utils.genericUnpack7Bit((byte[])s, Arrays.copyOfRange(publicKey, seedSk.length, publicKey.length),
                n - k, params.getDenselyPackedFpSynSize());
        }
        else
        {
            engine.expandPk(params, (short[][])V_tr, W_mat, seedSk);
            // Unpack syndrome
            isPaddKeyOk = Utils.genericUnpack9Bit((short[])s, Arrays.copyOfRange(publicKey, seedSk.length, publicKey.length),
                n - k, params.getDenselyPackedFpSynSize());
        }

        // Compute digest_msg_cmt_salt
        byte[] digestChall1 = new byte[hashDigestLength];

        engine.hash(digestChall1, 0, message, 0, message.length, CrossEngine.HASH_DOMAIN_SEP);
        engine.hash(digestChall1, 0, digestChall1, digest_cmt, salt, CrossEngine.HASH_DOMAIN_SEP);
        engine.init(digestChall1, digestChall1.length, CrossEngine.CSPRNG_DOMAIN_SEP_CONST + (3 * t - 1));
        // Generate challenge 1 vector
        int[] chall1 = engine.csprngFpVecChall1(params);

        // Expand challenge 2 to fixed weight
        byte[] chall2 = new byte[t];
        engine.expandDigestToFixedWeight(chall2, digestChall2, 0, params);

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

        int usedRsps = 0;
        boolean isSignatureOk = true;
        boolean isPackedPaddOk = true;
        int domainSepCsprng = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + (2 * t - 1);
        int domainSepHash = CrossEngine.HASH_DOMAIN_SEP_CONST + (2 * t - 1);
        for (int i = 0; i < t; i++, domainSepCsprng++, domainSepHash++)
        {
            if (chall2[i] == 1)
            {
                // Round with challenge=1
                engine.hash(cmt1, i * hashDigestLength, roundSeeds, i * seedLength, seedLength, salt, 0, saltLength, Pack.shortToLittleEndian((short)domainSepHash));

                engine.init(roundSeeds, i * seedLength, seedLength, salt, domainSepCsprng);
                if (params.rsdp)
                {
                    engine.csprngFVec(e_bar_prime, z, n, Utils.roundUp(params.getBitsNFzCtRng(), 8) >>> 3);
                    engine.csprngFVec((byte[])u_prime, params.getP(), n, Utils.roundUp(params.getBitsNFpCtRng(), 8) >>> 3);
                    CrossEngine.fpVecByRestrVecScaled(((byte[][])y)[i], e_bar_prime, chall1[i], (byte[])u_prime, params);
                    CrossEngine.fDzNorm(((byte[][])y)[i], n);
                }
                else
                {
                    byte[] e_G_bar_prime = new byte[m];
                    engine.csprngFVec(e_G_bar_prime, z, m, Utils.roundUp(params.getBitsMFzCtRng(), 8) >>> 3);
                    CrossEngine.fzInfWByFzMatrix(e_bar_prime, e_G_bar_prime, W_mat, params);
                    CrossEngine.fDzNorm(e_bar_prime, e_bar_prime.length);
                    engine.csprngFpVec((short[])u_prime, params);
                    CrossEngine.fpVecByRestrVecScaled(((short[][])y)[i], e_bar_prime, chall1[i], (short[])u_prime, params);
                }
            }
            else
            {
                // Round with challenge=0
                System.arraycopy(resp_1[usedRsps], 0, cmt1, i * hashDigestLength, hashDigestLength);
                if (params.rsdp)
                {
                    isPackedPaddOk &= Utils.genericUnpack7Bit(((byte[][])y)[i], resp0[usedRsps].y, n, params.getDenselyPackedFpVecSize());
                    byte[] v_bar = new byte[n];
                    isPackedPaddOk &= Utils.genericUnpack3Bit(v_bar, resp0[usedRsps].v_bar, n);
                    System.arraycopy(resp0[usedRsps].v_bar, 0, cmt0_i_input, packedFpSynSize, packedFzVecSize);
                    isSignatureOk &= CrossEngine.isFzVecInRestrGroupN(v_bar, params);

                    CrossEngine.convertRestrVecToFp((byte[])v, v_bar, params);
                    CrossEngine.fpVecByFpVecPointwise((byte[])y_prime, (byte[])v, ((byte[][])y)[i], params);
                    CrossEngine.fpVecByFpMatrix((byte[])y_prime_H, (byte[])y_prime, (byte[][])V_tr, params);
                    CrossEngine.fDzNorm((byte[])y_prime_H, ((byte[])y_prime_H).length);
                    CrossEngine.fpSyndMinusFpVecScaled((byte[])s_prime, (byte[])y_prime_H, (byte)chall1[i], (byte[])s, params);
                    CrossEngine.fDzNorm((byte[])s_prime, ((byte[])s_prime).length);

                    Utils.genericPack7Bit(cmt0_i_input, 0, (byte[])s_prime, ((byte[])s_prime).length);
                }
                else
                {
                    isPackedPaddOk &= Utils.genericUnpack9Bit(((short[][])y)[i], resp0[usedRsps].y, n, params.getDenselyPackedFpVecSize());
                    byte[] v_G_bar = new byte[m];
                    isPackedPaddOk &= Utils.genericUnpack7Bit(v_G_bar, resp0[usedRsps].v_bar, m, params.getDenselyPackedFzRsdpGVecSize());
                    isSignatureOk &= CrossEngine.isFzVecInRestrGroupM(v_G_bar, z, m);
                    byte[] v_bar = new byte[n];

                    CrossEngine.fzInfWByFzMatrix(v_bar, v_G_bar, W_mat, params);

                    CrossEngine.convertRestrVecToFp((short[])v, v_bar, params);
                    CrossEngine.fpVecByFpVecPointwise((short[])y_prime, (short[])v, ((short[][])y)[i], params);
                    CrossEngine.fpVecByFpMatrix((short[])y_prime_H, (short[])y_prime, (short[][])V_tr, params);
                    CrossEngine.fpSyndMinusFpVecScaled((short[])s_prime, (short[])y_prime_H, (short)chall1[i], (short[])s, params);
                    Utils.genericPack9Bit(cmt0_i_input, 0, (short[])s_prime);
                    System.arraycopy(resp0[usedRsps].v_bar, 0, cmt0_i_input, packedFpSynSize, packedFzRsdpGVecSize);
                }

                engine.hash(cmt0[i], 0, cmt0_i_input, 0, cmt0_i_input.length, Pack.shortToLittleEndian((short)domainSepHash));
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
            isMtreePaddingOk = engine.recomputeRootTreeBased(digestCmt0Cmt1, cmt0, proof, chall2, params);
        }

        //byte[] cmt1Hash = new byte[hashDigestLength];
        byte[] digestCmtPrime = new byte[hashDigestLength];
        engine.hash(digestCmtPrime, 0, cmt1, 0, cmt1.length, CrossEngine.HASH_DOMAIN_SEP);
        engine.hash(digestCmtPrime, 0, digestCmt0Cmt1, 0, hashDigestLength, digestCmtPrime, 0, hashDigestLength, CrossEngine.HASH_DOMAIN_SEP);

        // Compute challenge 2 prime
        int packedFpVecSize = params.getDenselyPackedFpVecSize();
        byte[] yDigestChall1 = new byte[t * packedFpVecSize + hashDigestLength];
        for (int i = 0; i < t; i++)
        {
            if (params.rsdp)
            {
                Utils.genericPack7Bit(yDigestChall1, i * packedFpVecSize, ((byte[][])y)[i], ((byte[][])y)[i].length);
            }
            else
            {
                Utils.genericPack9Bit(yDigestChall1, i * packedFpVecSize, ((short[][])y)[i]);
            }
        }
        System.arraycopy(digestChall1, 0, yDigestChall1, t * packedFpVecSize, hashDigestLength);

        byte[] digestChall2Prime = new byte[hashDigestLength];
        engine.hash(digestChall2Prime, 0, yDigestChall1, 0, yDigestChall1.length, CrossEngine.HASH_DOMAIN_SEP);

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
        public byte[] v_bar; // For RSDP; for RSDPG, v_G_bar
    }
}
