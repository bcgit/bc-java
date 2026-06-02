package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.util.Arrays;

/**
 * Top-level FAEST sign and verify orchestrator.
 * <p>
 * Wires together {@link VOLE#commit}/{@link VOLE#reconstruct}, the
 * {@link UniversalHashing#voleHash vole-hash}, the witness expansion
 * ({@link AesWitnessExtension}), the constraint prover/verifier
 * ({@link FaestProof}), {@link BAVC#open}, and the H_2/H_3/H_4 transcript
 * hashes from {@link RandomOracle} into the FAEST sign/verify pair.
 * <p>
 * Signature layout (faest-ref {@code faest.c:22-94}):
 * <pre>
 *   c[0..tau-2]   (tau-1) * (ell/8 + 3*lambda/8 + UNIVERSAL_HASH_B)  bytes
 *   u_tilde        lambda/8 + UNIVERSAL_HASH_B                      bytes
 *   d              ell/8                                            bytes
 *   a1_tilde       lambda/8                                         bytes
 *   a2_tilde       lambda/8                                         bytes
 *   decom_i        (variable, ends sig_size - lambda/8 - IV_SIZE - 4)
 *   chall_3        lambda/8                                         bytes
 *   iv_pre         IV_SIZE                                          bytes
 *   ctr            4                                                bytes
 * </pre>
 * faest-ref source of truth: {@code faest.c}.
 */
final class Faest
{
    private Faest()
    {
    }

    // ----- signature layout helpers -----

    private static int ellHatBytes(FaestParameters p)
    {
        return p.getEll() / 8 + 3 * p.getLambdaBytes() + FaestParameters.UNIVERSAL_HASH_B;
    }

    private static int utildeBytes(FaestParameters p)
    {
        return p.getLambdaBytes() + FaestParameters.UNIVERSAL_HASH_B;
    }

    static int sigOffsetC(int i, FaestParameters p)
    {
        return i * ellHatBytes(p);
    }

    static int sigOffsetUTilde(FaestParameters p)
    {
        return (p.getTau() - 1) * ellHatBytes(p);
    }

    static int sigOffsetD(FaestParameters p)
    {
        return sigOffsetUTilde(p) + utildeBytes(p);
    }

    static int sigOffsetA1Tilde(FaestParameters p)
    {
        return sigOffsetD(p) + p.getEll() / 8;
    }

    static int sigOffsetA2Tilde(FaestParameters p)
    {
        return sigOffsetA1Tilde(p) + p.getLambdaBytes();
    }

    static int sigOffsetDecomI(FaestParameters p)
    {
        return sigOffsetA2Tilde(p) + p.getLambdaBytes();
    }

    static int sigOffsetChall3(FaestParameters p)
    {
        return p.getSigSize() - 4 - FaestParameters.IV_SIZE - p.getLambdaBytes();
    }

    static int sigOffsetIvPre(FaestParameters p)
    {
        return p.getSigSize() - 4 - FaestParameters.IV_SIZE;
    }

    static int sigOffsetCtr(FaestParameters p)
    {
        return p.getSigSize() - 4;
    }

    static int sigSizeDecomI(FaestParameters p)
    {
        return sigOffsetChall3(p) - sigOffsetDecomI(p);
    }

    // ----- hash helpers (faest.c:175-282) -----

    private static void hashMu(byte[] mu, byte[] owfIn, byte[] owfOut, byte[] msg,
                               int msgOff, int msgLen, int lambda)
    {
        int lambdaBytes = lambda / 8;
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(owfIn);
        ro.absorb(owfOut);
        ro.absorb(msg, msgOff, msgLen);
        ro.absorbByte(RandomOracle.DOMAIN_H2_0);
        ro.squeeze(mu, 0, 2 * lambdaBytes);
    }

    private static void hashIv(byte[] iv, int ivOff, byte[] ivPre, int ivPreOff, int lambda)
    {
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(ivPre, ivPreOff, FaestParameters.IV_SIZE);
        ro.absorbByte(RandomOracle.DOMAIN_H4);
        ro.squeeze(iv, ivOff, FaestParameters.IV_SIZE);
    }

    private static void hashRIv(byte[] rootKey, byte[] sig, int ivPreSigOff,
                                byte[] iv, byte[] owfKey, byte[] mu, byte[] rho, int lambda)
    {
        int lambdaBytes = lambda / 8;
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(owfKey);
        ro.absorb(mu, 0, 2 * lambdaBytes);
        if (rho != null && rho.length > 0)
        {
            ro.absorb(rho);
        }
        ro.absorbByte(RandomOracle.DOMAIN_H3);
        ro.squeeze(rootKey, 0, lambdaBytes);
        ro.squeeze(sig, ivPreSigOff, FaestParameters.IV_SIZE);
        hashIv(iv, 0, sig, ivPreSigOff, lambda);
    }

    private static void hashChallenge1(byte[] chall1, byte[] mu, byte[] hcom,
                                       byte[] sig, int cOff, byte[] iv,
                                       int lambda, int ell, int tau)
    {
        int lambdaBytes = lambda / 8;
        int ellHatBytes = ell / 8 + 3 * lambdaBytes + FaestParameters.UNIVERSAL_HASH_B;
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(mu, 0, 2 * lambdaBytes);
        ro.absorb(hcom, 0, 2 * lambdaBytes);
        ro.absorb(sig, cOff, ellHatBytes * (tau - 1));
        ro.absorb(iv, 0, FaestParameters.IV_SIZE);
        ro.absorbByte(RandomOracle.DOMAIN_H2_1);
        ro.squeeze(chall1, 0, 5 * lambdaBytes + 8);
    }

    private static RandomOracle hashChallenge2Init(byte[] chall1, byte[] sig, int uTildeOff,
                                                   int lambda)
    {
        int lambdaBytes = lambda / 8;
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(chall1, 0, 5 * lambdaBytes + 8);
        ro.absorb(sig, uTildeOff, lambdaBytes + FaestParameters.UNIVERSAL_HASH_B);
        return ro;
    }

    private static void hashChallenge2UpdateVTilde(RandomOracle ctx, byte[] vTilde, int lambda)
    {
        int lambdaBytes = lambda / 8;
        ctx.absorb(vTilde, 0, lambdaBytes + FaestParameters.UNIVERSAL_HASH_B);
    }

    private static void hashChallenge2Finalize(byte[] chall2, RandomOracle ctx,
                                               byte[] sig, int dOff, int lambda, int ell)
    {
        int lambdaBytes = lambda / 8;
        ctx.absorb(sig, dOff, ell / 8);
        ctx.absorbByte(RandomOracle.DOMAIN_H2_2);
        ctx.squeeze(chall2, 0, 3 * lambdaBytes + 8);
    }

    private static RandomOracle hashChallenge3Init(byte[] chall2, byte[] a0Tilde,
                                                   byte[] sig, int a1SigOff, int a2SigOff,
                                                   int lambda)
    {
        int lambdaBytes = lambda / 8;
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(chall2, 0, 3 * lambdaBytes + 8);
        ro.absorb(a0Tilde);
        ro.absorb(sig, a1SigOff, lambdaBytes);
        ro.absorb(sig, a2SigOff, lambdaBytes);
        return ro;
    }

    private static void hashChallenge3Final(byte[] sig, int chall3Off, RandomOracle ctx,
                                            int ctr, int lambda)
    {
        int lambdaBytes = lambda / 8;
        // Copy then update so the original context can be re-used for another ctr.
        RandomOracle copy = ctx.copy();
        byte[] le = new byte[4];
        le[0] = (byte)ctr; le[1] = (byte)(ctr >>> 8); le[2] = (byte)(ctr >>> 16); le[3] = (byte)(ctr >>> 24);
        copy.absorb(le);
        copy.absorbByte(RandomOracle.DOMAIN_H2_3);
        copy.squeeze(sig, chall3Off, lambdaBytes);
    }

    private static void hashChallenge3OneShot(byte[] chall3, byte[] chall2, byte[] a0Tilde,
                                              byte[] sig, int a1SigOff, int a2SigOff,
                                              int ctr, int lambda)
    {
        int lambdaBytes = lambda / 8;
        RandomOracle ro = hashChallenge3Init(chall2, a0Tilde, sig, a1SigOff, a2SigOff, lambda);
        byte[] le = new byte[4];
        le[0] = (byte)ctr; le[1] = (byte)(ctr >>> 8); le[2] = (byte)(ctr >>> 16); le[3] = (byte)(ctr >>> 24);
        ro.absorb(le);
        ro.absorbByte(RandomOracle.DOMAIN_H2_3);
        ro.squeeze(chall3, 0, lambdaBytes);
    }

    /** True iff bits {@code start..lambda} of {@code chall3} are all zero — the
     *  proof-of-work grind condition (faest-ref {@code check_challenge_3}). */
    private static boolean checkChallenge3(byte[] chall3, int start, int lambda)
    {
        for (int b = start; b < lambda; b++)
        {
            if (((chall3[b >> 3] >>> (b & 7)) & 1) != 0)
            {
                return false;
            }
        }
        return true;
    }

    /** Decode chall_3 into tau indices, each k or k-1 bits long. Returns null if
     *  any index exceeds the corresponding {@code Ni}. faest-ref:
     *  {@code decode_all_chall_3}. */
    private static int[] decodeAllChall3(byte[] chall3, FaestParameters params)
    {
        int tau = params.getTau();
        int tau1 = params.getTau1();
        int k = params.getK();
        int[] out = new int[tau];
        for (int i = 0; i < tau; i++)
        {
            int lo, hi;
            if (i < tau1)
            {
                lo = i * k; hi = (i + 1) * k;
            }
            else
            {
                int t = i - tau1;
                lo = tau1 * k + t * (k - 1);
                hi = tau1 * k + (t + 1) * (k - 1);
            }
            int v = 0;
            for (int j = lo; j < hi; j++)
            {
                v |= ((chall3[j >> 3] >>> (j & 7)) & 1) << (j - lo);
            }
            int ni = BAVC.maxNodeIndex(i, tau1, k);
            if (v >= ni)
            {
                return null;
            }
            out[i] = v;
        }
        return out;
    }

    /**
     * Compute the FAEST one-way function output {@code y = OWF(key, input)} per
     * the parameter set.
     * <ul>
     *   <li>Non-EM (lambda=128): AES-128 encryption.</li>
     *   <li>Non-EM (lambda=192/256): two parallel AES-192/AES-256 encryptions of
     *       {@code (input, input XOR 1)} concatenated.</li>
     *   <li>EM (lambda=128): AES-128 with key = {@code input}, plaintext = {@code key};
     *       result XOR'd with {@code key}.</li>
     *   <li>EM (lambda=192/256): Rijndael-192/256 (192/256-bit block) analogue.</li>
     * </ul>
     */
    static void owf(byte[] key, byte[] input, byte[] output, FaestParameters p)
    {
        int lambda = p.getLambda();
        if (p.isEm())
        {
            if (lambda == 128)
            {
                FaestAES.aes128EncryptBlock(input, 0, key, 0, output, 0);
            }
            else if (lambda == 192)
            {
                FaestAES.rijndael192EncryptBlock(input, 0, key, 0, output, 0);
            }
            else
            {
                FaestAES.rijndael256EncryptBlock(input, 0, key, 0, output, 0);
            }
            for (int i = 0; i < output.length; i++)
            {
                output[i] ^= key[i];
            }
            return;
        }
        if (lambda == 128)
        {
            FaestAES.aes128EncryptBlock(key, 0, input, 0, output, 0);
        }
        else if (lambda == 192)
        {
            FaestAES.aes192EncryptBlock(key, 0, input, 0, output, 0);
            byte[] in2 = (byte[])input.clone();
            in2[0] ^= 0x01;
            FaestAES.aes192EncryptBlock(key, 0, in2, 0, output, 16);
        }
        else
        {
            FaestAES.aes256EncryptBlock(key, 0, input, 0, output, 0);
            byte[] in2 = (byte[])input.clone();
            in2[0] ^= 0x01;
            FaestAES.aes256EncryptBlock(key, 0, in2, 0, output, 16);
        }
    }

    // ----- public API -----

    /**
     * FAEST sign. Writes the signature to {@code sig[0..p.getSigSize()]}.
     * faest-ref: {@code faest_sign}, faest.c:304.
     */
    static void sign(byte[] sig, byte[] msg, byte[] owfKey, byte[] owfInput,
                     byte[] owfOutput, byte[] rho, FaestParameters p)
    {
        final int ell = p.getEll();
        final int ellBytes = ell / 8;
        final int lambda = p.getLambda();
        final int lambdaBytes = p.getLambdaBytes();
        final int tau = p.getTau();
        final int ellHat = ell + 3 * lambda + 8 * FaestParameters.UNIVERSAL_HASH_B;
        final int ellHatBytes = ellHat / 8;
        final int wGrind = p.getWGrind();

        byte[] mu = new byte[2 * lambdaBytes];
        hashMu(mu, owfInput, owfOutput, msg, 0, msg.length, lambda);

        byte[] rootKey = new byte[lambdaBytes];
        byte[] iv = new byte[FaestParameters.IV_SIZE];
        hashRIv(rootKey, sig, sigOffsetIvPre(p), iv, owfKey, mu, rho, lambda);

        VOLE.Commit voleCommit = VOLE.commit(rootKey, iv, ellHat, p);
        // Copy c into the signature.
        System.arraycopy(voleCommit.c, 0, sig, sigOffsetC(0, p), voleCommit.c.length);

        byte[] chall1 = new byte[5 * lambdaBytes + 8];
        hashChallenge1(chall1, mu, voleCommit.bavc.h, sig, sigOffsetC(0, p), iv, lambda, ell, tau);

        // Compute u_tilde = vole_hash(chall1, u).
        UniversalHashing.voleHash(sig, sigOffsetUTilde(p), chall1, 0, voleCommit.u, 0, ell, lambda);

        // chall_2 = H2(chall_1 || u_tilde || V_tilde[0..lambda] || d) with DOMAIN_H2_2.
        RandomOracle chall2Ctx = hashChallenge2Init(chall1, sig, sigOffsetUTilde(p), lambda);
        byte[] vTilde = new byte[lambdaBytes + FaestParameters.UNIVERSAL_HASH_B];
        for (int i = 0; i < lambda; i++)
        {
            UniversalHashing.voleHash(vTilde, 0, chall1, 0, voleCommit.v[i], 0, ell, lambda);
            hashChallenge2UpdateVTilde(chall2Ctx, vTilde, lambda);
        }

        byte[] w = AesWitnessExtension.extendWitness(owfKey, owfInput, p);
        // d = w XOR u (only ell/8 bytes — w is exactly ell bits packed)
        for (int i = 0; i < ellBytes; i++)
        {
            sig[sigOffsetD(p) + i] = (byte)(w[i] ^ voleCommit.u[i]);
        }

        byte[] chall2 = new byte[3 * lambdaBytes + 8];
        hashChallenge2Finalize(chall2, chall2Ctx, sig, sigOffsetD(p), lambda, ell);

        byte[] wBits = new byte[ell];
        for (int i = 0; i < ell; i++)
        {
            wBits[i] = (byte)((w[i >> 3] >>> (i & 7)) & 1);
        }
        byte[] uBits = new byte[2 * lambda];
        for (int i = 0; i < 2 * lambda; i++)
        {
            int srcBit = ell + i;
            uBits[i] = (byte)((voleCommit.u[srcBit >> 3] >>> (srcBit & 7)) & 1);
        }
        byte[] a0Tilde = new byte[lambdaBytes];
        byte[] a1Tilde = new byte[lambdaBytes];
        byte[] a2Tilde = new byte[lambdaBytes];
        FaestProof.aesProve(a0Tilde, a1Tilde, a2Tilde, wBits, uBits, voleCommit.v,
            owfInput, owfOutput, chall2, p);
        System.arraycopy(a1Tilde, 0, sig, sigOffsetA1Tilde(p), lambdaBytes);
        System.arraycopy(a2Tilde, 0, sig, sigOffsetA2Tilde(p), lambdaBytes);

        // Counter-based grind: try ctr until chall_3 satisfies check_challenge_3 and
        // decode_all_chall_3, and BAVC.open succeeds.
        RandomOracle chall3Ctx = hashChallenge3Init(chall2, a0Tilde, sig,
            sigOffsetA1Tilde(p), sigOffsetA2Tilde(p), lambda);
        int ctr = 0;
        byte[] decomI = null;
        while (true)
        {
            hashChallenge3Final(sig, sigOffsetChall3(p), chall3Ctx, ctr, lambda);
            byte[] chall3 = Arrays.copyOfRange(sig, sigOffsetChall3(p),
                sigOffsetChall3(p) + lambdaBytes);
            if (!checkChallenge3(chall3, lambda - wGrind, lambda))
            {
                ctr++;
                continue;
            }
            int[] decoded = decodeAllChall3(chall3, p);
            if (decoded == null)
            {
                ctr++;
                continue;
            }
            byte[] candidate = BAVC.open(voleCommit.bavc, decoded, p);
            if (candidate != null)
            {
                decomI = candidate;
                break;
            }
            ctr++;
        }
        System.arraycopy(decomI, 0, sig, sigOffsetDecomI(p), decomI.length);

        // counter (little-endian uint32)
        sig[sigOffsetCtr(p)]     = (byte)ctr;
        sig[sigOffsetCtr(p) + 1] = (byte)(ctr >>> 8);
        sig[sigOffsetCtr(p) + 2] = (byte)(ctr >>> 16);
        sig[sigOffsetCtr(p) + 3] = (byte)(ctr >>> 24);
    }

    /**
     * FAEST verify. Returns 0 on success, a negative value on failure.
     * faest-ref: {@code faest_verify}, faest.c:426.
     */
    static int verify(byte[] msg, byte[] sig, byte[] owfInput, byte[] owfOutput,
                      FaestParameters p)
    {
        final int ell = p.getEll();
        final int lambda = p.getLambda();
        final int lambdaBytes = p.getLambdaBytes();
        final int tau = p.getTau();
        final int ellHat = ell + 3 * lambda + 8 * FaestParameters.UNIVERSAL_HASH_B;
        final int ellHatBytes = ellHat / 8;
        final int utildeBytes = lambdaBytes + FaestParameters.UNIVERSAL_HASH_B;

        byte[] chall3 = Arrays.copyOfRange(sig, sigOffsetChall3(p),
            sigOffsetChall3(p) + lambdaBytes);
        if (!checkChallenge3(chall3, lambda - p.getWGrind(), lambda))
        {
            return -2;
        }

        byte[] mu = new byte[2 * lambdaBytes];
        hashMu(mu, owfInput, owfOutput, msg, 0, msg.length, lambda);

        byte[] iv = new byte[FaestParameters.IV_SIZE];
        hashIv(iv, 0, sig, sigOffsetIvPre(p), lambda);

        int[] decoded = decodeAllChall3(chall3, p);
        if (decoded == null)
        {
            return -2;
        }

        // Reconstruct VOLE matrix Q.
        byte[] decomI = Arrays.copyOfRange(sig, sigOffsetDecomI(p),
            sigOffsetDecomI(p) + sigSizeDecomI(p));
        byte[] c = Arrays.copyOfRange(sig, sigOffsetC(0, p), sigOffsetC(0, p) + (tau - 1) * ellHatBytes);
        VOLE.Reconstruct rec = VOLE.reconstruct(decomI, decoded, iv, c, ellHat, p);
        if (rec == null)
        {
            return -3;
        }

        byte[] chall1 = new byte[5 * lambdaBytes + 8];
        hashChallenge1(chall1, mu, rec.com, sig, sigOffsetC(0, p), iv, lambda, ell, tau);

        RandomOracle chall2Ctx = hashChallenge2Init(chall1, sig, sigOffsetUTilde(p), lambda);
        byte[] qTilde = new byte[lambdaBytes + FaestParameters.UNIVERSAL_HASH_B];
        for (int i = 0; i < lambda; i++)
        {
            UniversalHashing.voleHash(qTilde, 0, chall1, 0, rec.q[i], 0, ell, lambda);
            int chall3Bit = (chall3[i >> 3] >>> (i & 7)) & 1;
            if (chall3Bit != 0)
            {
                for (int b = 0; b < utildeBytes; b++)
                {
                    qTilde[b] ^= sig[sigOffsetUTilde(p) + b];
                }
            }
            hashChallenge2UpdateVTilde(chall2Ctx, qTilde, lambda);
        }
        byte[] chall2 = new byte[3 * lambdaBytes + 8];
        hashChallenge2Finalize(chall2, chall2Ctx, sig, sigOffsetD(p), lambda, ell);

        byte[] dBits = new byte[ell];
        for (int i = 0; i < ell; i++)
        {
            dBits[i] = (byte)((sig[sigOffsetD(p) + (i >> 3)] >>> (i & 7)) & 1);
        }
        byte[] a1Tilde = Arrays.copyOfRange(sig, sigOffsetA1Tilde(p),
            sigOffsetA1Tilde(p) + lambdaBytes);
        byte[] a2Tilde = Arrays.copyOfRange(sig, sigOffsetA2Tilde(p),
            sigOffsetA2Tilde(p) + lambdaBytes);
        byte[] a0Tilde = FaestProof.aesVerify(dBits, rec.q, chall2, chall3, a1Tilde, a2Tilde,
            owfInput, owfOutput, p);

        int ctr = (sig[sigOffsetCtr(p)] & 0xff)
            | ((sig[sigOffsetCtr(p) + 1] & 0xff) << 8)
            | ((sig[sigOffsetCtr(p) + 2] & 0xff) << 16)
            | ((sig[sigOffsetCtr(p) + 3] & 0xff) << 24);
        byte[] expected = new byte[lambdaBytes];
        hashChallenge3OneShot(expected, chall2, a0Tilde, sig,
            sigOffsetA1Tilde(p), sigOffsetA2Tilde(p), ctr, lambda);

        return Arrays.constantTimeAreEqual(expected, chall3) ? 0 : -1;
    }
}
