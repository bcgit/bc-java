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
        int m = params.getM();
        int w = params.getW();
        int t = params.getT();
        int k = params.getK();
        int n = params.getN();
        int z = params.getZ();
        int p = params.getP();
        int hashDigestLength = params.getHashDigestLength();
        byte[] sm = new byte[params.getSignatureSize() + message.length];
        int pos = 0;
        byte[] salt = new byte[hashDigestLength]; //digest_chall_1
        // Key material expansion
        byte[] e_bar = new byte[n];
        // Prepare arrays for T rounds
        byte[][] e_bar_prime = new byte[t][n];
        byte[][] v_bar = new byte[t][n];
        // Generate root seed and salt
        byte[] root_seed = new byte[params.getSeedLengthBytes()];
        // Generate round seeds
        byte[] round_seeds = new byte[t * params.getSeedLengthBytes()];
        byte[] seed_tree = null;

        int keypairSeedLen = params.getKeypairSeedLengthBytes();
        byte[][] seedESeedPk = new byte[2][keypairSeedLen];
        // Prepare commitment inputs
        byte[] cmt0 = new byte[t * hashDigestLength];
        byte[] cmt1 = new byte[t * hashDigestLength];
        // Compute root digests
        byte[] digest_cmt0_cmt1 = new byte[2 * hashDigestLength];
        byte[] merkle_tree_0 = null;
        byte[] chall_2 = new byte[t];
        byte[] cmt0_i_input = new byte[params.getDenselyPackedFpSynSize()];
        byte[] seed_sk = privKey.getEncoded();
        System.arraycopy(message, 0, sm, pos, message.length);
        pos += message.length;
        random.nextBytes(root_seed);
        random.nextBytes(salt);
        System.arraycopy(salt, 0, sm, pos, salt.length);
        pos += salt.length;

        if (params.variant == CrossParameters.FAST)
        {
            engine.seedLeavesSpeed(round_seeds, root_seed, salt);
        }
        else
        {
            seed_tree = new byte[params.getNumNodesSeedTree() * params.getSeedLengthBytes()];
            merkle_tree_0 = new byte[params.getNumNodesMerkleTree() * hashDigestLength];
            engine.genSeedTree(seed_tree, root_seed, salt);
            engine.seedLeavesTree(round_seeds, seed_tree);
        }
        // Step 1: Initialize CSPRNG for secret key expansion
        engine.init(seed_sk, seed_sk.length, 3 * t + 1);

        // Step 2: Generate seeds for error vector and public key
        engine.randomBytes(seedESeedPk[0], keypairSeedLen);
        engine.randomBytes(seedESeedPk[1], keypairSeedLen);
        engine.init(seedESeedPk[0], seedESeedPk[0].length, 3 * t + 3);
        int bufferSize;
        if (params.rsdp)
        {
            byte[][] V_tr = new byte[k][n - k];
            byte[][] y = new byte[t][Math.max(params.getDenselyPackedFpVecSize(), n)]; //u_prime
            byte[] s_prime = new byte[n - k];
            byte[] u = new byte[n]; //v
            bufferSize = params.getBitsNFzCtRng();
            int bufferSize_y = params.getBitsNFpCtRng();
            engine.csprngFVec(e_bar, z, n, bufferSize);
            engine.expandPk(V_tr, seedESeedPk[1]);

            // Process each round
            for (int i = 0, domain_sep_csprng = 2 * t - 1, domain_sep_hash = CrossEngine.HASH_DOMAIN_SEP_CONST + domain_sep_csprng; i < t; i++, domain_sep_hash++, domain_sep_csprng++)
            {
                // Prepare CSPRNG input
                engine.init(round_seeds, i * params.getSeedLengthBytes(), params.getSeedLengthBytes(), salt, domain_sep_csprng);
                engine.csprngFVec(e_bar_prime[i], z, n, bufferSize);
                // Compute v_bar
                // This function may use (((x) & 0x07) + ((x) >> 3)) 
                CrossEngine.fzVecSub(v_bar[i], e_bar, e_bar_prime[i], n);
                CrossEngine.convertRestrVecToFp(u, v_bar[i], n);
                CrossEngine.fDzNorm(v_bar[i], v_bar[i].length);
                // Convert to FP and compute u_prime
                engine.csprngFVec(y[i], p, n, bufferSize_y);
                // Compute s_prime
                CrossEngine.fpVecByFpVecPointwise(u, u, y[i], n);
                CrossEngine.fpVecByFpMatrix(s_prime, u, V_tr, k, n - k);
                CrossEngine.fDzNorm(s_prime, n - k);

                // Build cmt_0 input
                Utils.genericPack7Bit(cmt0_i_input, 0, s_prime, n - k);
                Utils.genericPack3Bit(v_bar[i], 0, v_bar[i], n);
                // Compute commitments
                getCmt(hashDigestLength, salt, round_seeds, cmt0, cmt1, cmt0_i_input, v_bar[i], params.getDenselyPackedFzVecSize(), i, (short)domain_sep_hash);
            }
            int[] chall_1 = getChall1(message, t, hashDigestLength, sm, pos, salt, cmt0, cmt1, digest_cmt0_cmt1, merkle_tree_0);
            pos += hashDigestLength;
            for (int i = 0; i < t; i++)
            {
                CrossEngine.fpVecByRestrVecScaled(y[i], e_bar_prime[i], chall_1[i], y[i], n);
                CrossEngine.fDzNorm(y[i], n);
                Utils.genericPack7Bit(y[i], 0, y[i], y[i].length);
                engine.digest.update(y[i], 0, params.getDenselyPackedFpVecSize());
            }
            pos = getPathAndProof(w, hashDigestLength, sm, pos, salt, round_seeds, seed_tree, cmt0, merkle_tree_0, chall_2);
            packResp0(pos, hashDigestLength, t, w, chall_2, sm, y, params.getDenselyPackedFpVecSize(), v_bar, params.getDenselyPackedFzVecSize(), cmt1);
        }
        else
        {
            short[][] V_tr = new short[k][n - k];
            byte[] e_G_bar = new byte[m];
            byte[][] W_mat = new byte[m][n - m];
            short[][] y = new short[t][n];//u_prime
            byte[][] y_digest_chall = new byte[t][params.getDenselyPackedFpVecSize()];
            byte[][] v_G_bar = new byte[t][m];
            byte[] egBarPrime = new byte[m];
            short[] u = new short[n];
            short[] s_prime = new short[n - k];
            bufferSize = params.getBitsMFzCtRng();
            engine.csprngFVec(e_G_bar, z, m, bufferSize);
            engine.expandPk(V_tr, W_mat, seedESeedPk[1]);
            CrossEngine.fzInfWByFzMatrix(e_bar, e_G_bar, W_mat, m, n - m);
            int packedFzRsdpGVecSize = params.getDenselyPackedFzRsdpGVecSize();
            // Process each round
            for (int i = 0, domain_sep_csprng = 2 * t - 1, domain_sep_hash = CrossEngine.HASH_DOMAIN_SEP_CONST + domain_sep_csprng; i < t; i++, domain_sep_hash++, domain_sep_csprng++)
            {
                // Prepare CSPRNG input
                engine.init(round_seeds, i * params.getSeedLengthBytes(), params.getSeedLengthBytes(), salt, domain_sep_csprng);
                engine.csprngFVec(egBarPrime, z, m, bufferSize);
                CrossEngine.fzVecSub(v_G_bar[i], e_G_bar, egBarPrime, m);
                CrossEngine.fDzNorm(v_G_bar[i], m);
                CrossEngine.fzInfWByFzMatrix(e_bar_prime[i], egBarPrime, W_mat, m, n - m);
                //CrossEngine.fDzNorm(e_bar_prime[i], e_bar_prime[i].length);
                // Compute v_bar
                CrossEngine.fzVecSub(v_bar[i], e_bar, e_bar_prime[i], n);
                CrossEngine.convertRestrVecToFp(u, v_bar[i], n);
                //CrossEngine.fDzNorm(v_bar[i], v_bar[i].length);

                // Convert to FP and compute u_prime
                engine.csprngFpVec(y[i]);

                // Compute s_prime
                CrossEngine.fpVecByFpVecPointwise(u, u, y[i], n);
                CrossEngine.fpVecByFpMatrix(s_prime, u, V_tr, k, n - k);
                // Build cmt_0 input
                Utils.genericPack9Bit(cmt0_i_input, 0, s_prime, s_prime.length);
                Utils.genericPack7Bit(v_G_bar[i], 0, v_G_bar[i], m);
                // Compute commitments
                getCmt(hashDigestLength, salt, round_seeds, cmt0, cmt1, cmt0_i_input, v_G_bar[i], packedFzRsdpGVecSize, i, (short)domain_sep_hash);
            }
            int[] chall_1 = getChall1(message, t, hashDigestLength, sm, pos, salt, cmt0, cmt1, digest_cmt0_cmt1, merkle_tree_0);
            pos += hashDigestLength;
            for (int i = 0; i < t; i++)
            {
                CrossEngine.fpVecByRestrVecScaled(y[i], e_bar_prime[i], chall_1[i], y[i], n);
                Utils.genericPack9Bit(y_digest_chall[i], 0, y[i], n);
                engine.digest.update(y_digest_chall[i], 0, params.getDenselyPackedFpVecSize());
            }
            pos = getPathAndProof(w, hashDigestLength, sm, pos, salt, round_seeds, seed_tree, cmt0, merkle_tree_0, chall_2);
            packResp0(pos, hashDigestLength, t, w, chall_2, sm, y_digest_chall, params.getDenselyPackedFpVecSize(), v_G_bar, packedFzRsdpGVecSize, cmt1);
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
        int p = params.getP();
        int hashDigestLength = params.getHashDigestLength();
        int saltLength = params.getHashDigestLength();
        int seedLength = params.getSeedLengthBytes();
        // Expand public key based on variant
        byte[] digestChall1 = new byte[hashDigestLength];
        byte[] publicKey = pubKey.getEncoded();
        byte[] seedSk = Arrays.copyOf(publicKey, params.getKeypairSeedLengthBytes());
        int pos = message.length;
        byte[] cmt0 = new byte[t * hashDigestLength];
        byte[] cmt1 = new byte[t * hashDigestLength];
        byte[] roundSeeds = new byte[t * seedLength];
        boolean isStreePaddingOk;
        byte[] chall2 = new byte[t];
        byte[] v_bar = new byte[n]; //e_bar_prime
        int packedFpSynSize = params.getDenselyPackedFpSynSize();
        int packedFzVecSize = params.getDenselyPackedFzVecSize();
        int packedFzRsdpGVecSize = params.getDenselyPackedFzRsdpGVecSize();
        int packedFpVecSize = params.getDenselyPackedFpVecSize();
        byte[] yDigestChall1 = new byte[t * packedFpVecSize];
        byte[] digestCmt0Cmt1 = new byte[2 * hashDigestLength];
        byte[] cmt0_i_input1 = new byte[packedFpSynSize];
        boolean isMtreePaddingOk;
        int blockSize;
        int v_bar_size;
        int proofLength, pathLength;
        boolean isPaddKeyOk;
        int bufferSize;
        if (params.variant == CrossParameters.FAST)
        {
            proofLength = w * hashDigestLength;
            pathLength = w * params.getSeedLengthBytes();
        }
        else
        {
            proofLength = hashDigestLength * params.getTreeNodesToStore();
            pathLength = params.getTreeNodesToStore() * params.getSeedLengthBytes();
        }
        // Fixed-length components
        int saltPos = pos;
        pos += saltLength;

        int digestCmtPos = pos;
        pos += hashDigestLength;

        int digestChall2Pos = pos;
        pos += hashDigestLength;

        int pathPos = pos;
        pos += pathLength;

        int proofPos = pos;
        pos += proofLength;

        // resp_1: T elements of hash digest length
        int resp1Pos = pos;
        pos += (t - w) * hashDigestLength;
        int remainingBytes = signature.length - pos;
        if (params.rsdp)
        {
            blockSize = packedFpVecSize + params.getDenselyPackedFzVecSize();
            v_bar_size = params.getDenselyPackedFzVecSize();
        }
        else
        {
            blockSize = packedFpVecSize + packedFzRsdpGVecSize;
            v_bar_size = packedFzRsdpGVecSize;
        }
        int resp0Size = packedFpVecSize + v_bar_size;
        int resp0Pos = pos;
        if (remainingBytes % blockSize != 0)
        {
            throw new IllegalArgumentException("Invalid signature length");
        }

        int[] chall1 = getChall1(message, t, hashDigestLength, signature, digestCmtPos, digestChall1);
        engine.expandDigestToFixedWeight(chall2, signature, digestChall2Pos, params);
        // Rebuild seed tree
        if (params.variant == CrossParameters.FAST)
        {
            isStreePaddingOk = CrossEngine.rebuildLeaves(roundSeeds, chall2, signature, pathPos, seedLength);
        }
        else
        {
            byte[] seedTree = new byte[params.getNumNodesSeedTree() * seedLength];
            isStreePaddingOk = engine.rebuildTree(seedTree, chall2, signature, pathPos, signature, saltPos);
            engine.seedLeavesTree(roundSeeds, seedTree);
        }

        int usedRsps = 0;
        boolean isSignatureOk = true;
        boolean isPackedPaddOk = true;
        int domainSepCsprng = 2 * t - 1;
        short domainSepHash = (short)(CrossEngine.HASH_DOMAIN_SEP_CONST + domainSepCsprng);
        if (params.rsdp)
        {
            bufferSize = params.getBitsNFzCtRng();
            int bufferSize_y = params.getBitsNFpCtRng();
            byte[][] V_tr = new byte[k][n - k];
            byte[] s = new byte[n - k]; // s_prime, y_prime_H
            byte[] s_prime = new byte[n - k]; //y_prime_H
            engine.expandPk(V_tr, seedSk);
            byte[] y = new byte[n]; // y, u_prime
            // Unpack syndrome
            isPaddKeyOk = Utils.genericUnpack7Bit(s, publicKey, seedSk.length, n - k);
            for (int i = 0; i < t; i++, domainSepCsprng++, domainSepHash++)
            {
                if (chall2[i] == 1)
                {
                    // Round with challenge=1
                    engine.hash(cmt1, i * hashDigestLength, roundSeeds, i * seedLength, seedLength, signature, saltPos, saltLength, Pack.shortToLittleEndian(domainSepHash));
                    engine.init(roundSeeds, i * seedLength, seedLength, signature, saltPos, saltLength, domainSepCsprng);
                    engine.csprngFVec(v_bar, z, n, bufferSize);
                    engine.csprngFVec(y, p, n, bufferSize_y);
                    CrossEngine.fpVecByRestrVecScaled(y, v_bar, chall1[i], y, n);
                    CrossEngine.fDzNorm(y, n);
                    Utils.genericPack7Bit(yDigestChall1, i * packedFpVecSize, y, n);
                }
                else
                {
                    // Round with challenge=0
                    System.arraycopy(signature, resp1Pos + usedRsps * hashDigestLength, cmt1, i * hashDigestLength, hashDigestLength);
                    //v_bar: y_prime, v
                    int yPos = resp0Pos + usedRsps * resp0Size;
                    System.arraycopy(signature, yPos, yDigestChall1, i * packedFpVecSize, packedFpVecSize);
                    isPackedPaddOk &= Utils.genericUnpack7Bit(y, signature, yPos, n);
                    isPackedPaddOk &= Utils.genericUnpack3Bit(v_bar, signature, yPos + packedFpVecSize, n);
                    isSignatureOk &= CrossEngine.isFzVecInRestrGroup(v_bar, z, n);
                    CrossEngine.convertRestrVecToFp(v_bar, v_bar, n);
                    CrossEngine.fpVecByFpVecPointwise(v_bar, v_bar, y, n);
                    CrossEngine.fpVecByFpMatrix(s_prime, v_bar, V_tr, k, n - k);
                    //CrossEngine.fDzNorm(s_prime, s_prime.length);
                    CrossEngine.fpSyndMinusFpVecScaled(s_prime, s_prime, (byte)chall1[i], s, params);
                    //CrossEngine.fDzNorm(s_prime, s_prime.length);
                    Utils.genericPack7Bit(cmt0_i_input1, 0, s_prime, s_prime.length);
                    engine.hash(cmt0, i * hashDigestLength, cmt0_i_input1, signature, yPos + packedFpVecSize, packedFzVecSize,
                        signature, saltPos, saltLength, Pack.shortToLittleEndian(domainSepHash));
                    usedRsps++;
                }
            }
        }
        else
        {
            short[][] V_tr = new short[k][n - k];
            short[] s = new short[n - k];
            byte[][] W_mat = new byte[m][n - m];
            short[] u_prime = new short[n]; // v, y_prime
            short[] s_prime = new short[n - k];
            short[] y = new short[n];
            byte[] v_G_bar = new byte[m]; //e_G_bar_prime
            bufferSize = params.getBitsMFzCtRng();
            engine.expandPk(V_tr, W_mat, seedSk);
            // Unpack syndrome
            isPaddKeyOk = Utils.genericUnpack9Bit(s, publicKey, seedSk.length, n - k);
            for (int i = 0; i < t; i++, domainSepCsprng++, domainSepHash++)
            {
                if (chall2[i] == 1)
                {
                    // Round with challenge=1
                    engine.hash(cmt1, i * hashDigestLength, roundSeeds, i * seedLength, seedLength, signature, saltPos, saltLength, Pack.shortToLittleEndian(domainSepHash));
                    engine.init(roundSeeds, i * seedLength, seedLength, signature, saltPos, saltLength, domainSepCsprng);
                    engine.csprngFVec(v_G_bar, z, m, bufferSize);
                    CrossEngine.fzInfWByFzMatrix(v_bar, v_G_bar, W_mat, m, n - m);
                    //CrossEngine.fDzNorm(v_bar, v_bar.length);
                    engine.csprngFpVec(u_prime);
                    CrossEngine.fpVecByRestrVecScaled(u_prime, v_bar, chall1[i], u_prime, n);
                    Utils.genericPack9Bit(yDigestChall1, i * packedFpVecSize, u_prime, n);
                }
                else
                {
                    // Round with challenge=0
                    System.arraycopy(signature, resp1Pos + usedRsps * hashDigestLength, cmt1, i * hashDigestLength, hashDigestLength);
                    int yPos = resp0Pos + usedRsps * resp0Size;
                    System.arraycopy(signature, yPos, yDigestChall1, i * packedFpVecSize, packedFpVecSize);
                    isPackedPaddOk &= Utils.genericUnpack9Bit(y, signature, yPos, n);
                    isPackedPaddOk &= Utils.genericUnpack7Bit(v_G_bar, signature, yPos + packedFpVecSize, m);
                    isSignatureOk &= CrossEngine.isFzVecInRestrGroup(v_G_bar, z, m);
                    CrossEngine.fzInfWByFzMatrix(v_bar, v_G_bar, W_mat, m, n - m);
                    CrossEngine.convertRestrVecToFp(u_prime, v_bar, n);
                    CrossEngine.fpVecByFpVecPointwise(u_prime, u_prime, y, n);
                    CrossEngine.fpVecByFpMatrix(s_prime, u_prime, V_tr, k, n - k);
                    CrossEngine.fpSyndMinusFpVecScaled(s_prime, s_prime, (short)chall1[i], s, params);
                    Utils.genericPack9Bit(cmt0_i_input1, 0, s_prime, n - k);
                    engine.hash(cmt0, i * hashDigestLength, cmt0_i_input1, signature, yPos + packedFpVecSize,
                        packedFzRsdpGVecSize, signature, saltPos, saltLength, Pack.shortToLittleEndian(domainSepHash));
                    usedRsps++;
                }
            }
        }
        engine.hash(digestChall1, 0, yDigestChall1, 0, yDigestChall1.length, digestChall1, 0, hashDigestLength, CrossEngine.HASH_DOMAIN_SEP);
        boolean doesDigestChall2Match = Arrays.constantTimeAreEqual(hashDigestLength, digestChall1, 0, signature, digestChall2Pos);

        // Recompute Merkle root
        if (params.variant == CrossParameters.FAST)
        {
            isMtreePaddingOk = engine.recomputeRootSpeed(digestCmt0Cmt1, cmt0, signature, proofPos, chall2);
        }
        else
        {
            isMtreePaddingOk = engine.recomputeRootTreeBased(digestCmt0Cmt1, cmt0, signature, proofPos, chall2);
        }
        engine.hash(digestChall1, 0, cmt1, 0, cmt1.length, CrossEngine.HASH_DOMAIN_SEP);
        engine.hash(digestChall1, 0, digestCmt0Cmt1, 0, hashDigestLength, digestChall1, 0, hashDigestLength, CrossEngine.HASH_DOMAIN_SEP);
        boolean doesDigestCmtMatch = Arrays.constantTimeAreEqual(hashDigestLength, digestChall1, 0, signature, digestCmtPos);

        return isSignatureOk && doesDigestCmtMatch && doesDigestChall2Match &&
            isMtreePaddingOk && isStreePaddingOk && isPaddKeyOk && isPackedPaddOk;
    }

    private void getCmt(int hashDigestLength, byte[] salt, byte[] round_seeds, byte[] cmt_0, byte[] cmt_1, byte[] cmt0_i_input, byte[] cmt0_i_input1, int cmt0_i_input1_len, int i, short domain_sep_hash)
    {
        byte[] domain_sep_hash_bytes = Pack.shortToLittleEndian(domain_sep_hash);
        engine.hash(cmt_0, i * hashDigestLength, cmt0_i_input, cmt0_i_input1, 0, cmt0_i_input1_len, salt, 0, salt.length, domain_sep_hash_bytes);
        engine.hash(cmt_1, i * hashDigestLength, round_seeds, i * params.getSeedLengthBytes(), params.getSeedLengthBytes(),
            salt, 0, hashDigestLength, domain_sep_hash_bytes);
    }

    private int getPathAndProof(int w, int hashDigestLength, byte[] sm, int pos, byte[] salt, byte[] round_seeds, byte[] seed_tree, byte[] cmt_0, byte[] merkle_tree_0, byte[] chall_2)
    {
        engine.digest.update(salt, 0, salt.length);
        engine.digest.update(CrossEngine.HASH_DOMAIN_SEP, 0, 2);
        engine.digest.doFinal(sm, pos, hashDigestLength);

        // Expand to fixed weight challenge
        engine.expandDigestToFixedWeight(chall_2, sm, pos, params);
        pos += hashDigestLength;

        // Generate Merkle proofs
        if (params.variant == CrossParameters.FAST)
        {
            int seedLengthBytes = params.getSeedLengthBytes();
            int pos2 = pos + w * seedLengthBytes;
            for (int i = 0; i < chall_2.length; i++)
            {
                if (chall_2[i] == CrossEngine.TO_PUBLISH)
                {
                    System.arraycopy(round_seeds, i * seedLengthBytes, sm, pos, seedLengthBytes);
                    pos += seedLengthBytes;
                    System.arraycopy(cmt_0, i * hashDigestLength, sm, pos2, hashDigestLength);
                    pos2 += hashDigestLength;
                }
            }
            return pos2;
        }
        else
        {
            engine.seedPathBalanced(sm, pos, seed_tree, chall_2);
            pos += params.getTreeNodesToStore() * params.getSeedLengthBytes();
            engine.treeProofBalanced(sm, pos, merkle_tree_0, chall_2);
            pos += hashDigestLength * params.getTreeNodesToStore();
        }
        return pos;
    }

    private int[] getChall1(byte[] message, int t, int hashDigestLength, byte[] sm, int pos, byte[] salt, byte[] cmt_0, byte[] cmt_1, byte[] digest_cmt0_cmt1, byte[] merkle_tree_0)
    {
        if (params.variant == CrossParameters.FAST)
        {
            engine.treeRootSpeed(digest_cmt0_cmt1, cmt_0);
        }
        else
        {
            engine.treeRootBalanced(digest_cmt0_cmt1, merkle_tree_0, cmt_0);
        }

        engine.hash(digest_cmt0_cmt1, hashDigestLength, cmt_1, 0, cmt_1.length, CrossEngine.HASH_DOMAIN_SEP);
        engine.hash(sm, pos, digest_cmt0_cmt1, 0, digest_cmt0_cmt1.length, CrossEngine.HASH_DOMAIN_SEP);

        // First challenge extraction
        int[] chall_1 = getChall1(message, t, hashDigestLength, sm, pos, salt);
        engine.digest.reset();
        return chall_1;
    }

    private int[] getChall1(byte[] message, int t, int hashDigestLength, byte[] sm, int pos, byte[] tmp)
    {
        engine.hash(tmp, 0, message, 0, message.length, CrossEngine.HASH_DOMAIN_SEP);
        // hash(digest_chall_1 || digest_cmt || salt || dsc)
        engine.hash(tmp, 0, tmp, sm, pos, hashDigestLength, sm, message.length, hashDigestLength, CrossEngine.HASH_DOMAIN_SEP);
        engine.init(tmp, tmp.length, 3 * t - 1);
        return engine.csprngFpVecChall1();
    }

    private void packResp0(int pos, int hashDigestLength, int t, int w, byte[] chall_2, byte[] sm, byte[][] y, int yLen, byte[][] v_bar, int v_barLen, byte[] cmt1)
    {
        int published_rsps = 0;
        int pos2 = pos + hashDigestLength * (t - w);
        for (int i = 0; i < t; i++)
        {
            if (chall_2[i] == 0)
            {
                if (published_rsps++ >= t - w)
                {
                    Arrays.fill(sm, (byte)0);
                    throw new IllegalStateException("Too many responses to publish");
                }
                System.arraycopy(y[i], 0, sm, pos2, yLen);
                pos2 += yLen;
                System.arraycopy(v_bar[i], 0, sm, pos2, v_barLen);
                pos2 += v_barLen;
                System.arraycopy(cmt1, i * hashDigestLength, sm, pos, hashDigestLength);
                pos += hashDigestLength;
            }
        }
    }
}
