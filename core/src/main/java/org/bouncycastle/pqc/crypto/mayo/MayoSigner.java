package org.bouncycastle.pqc.crypto.mayo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.GF16;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

/**
 * Implementation of the MAYO digital signature scheme as specified in the MAYO documentation.
 * This class provides functionality for both signature generation and verification.
 *
 * <p>MAYO is a candidate in the <b>NIST Post-Quantum Cryptography: Additional Digital Signature Schemes</b> project,
 * currently in Round 2 of evaluations. For more details about the NIST standardization process, see:
 * <a href="https://csrc.nist.gov/Projects/pqc-dig-sig">NIST PQC Additional Digital Signatures</a>.</p>
 *
 * <p>References:</p>
 * <ul>
 *   <li><a href="https://pqmayo.org/">MAYO Official Website</a></li>
 *   <li><a href="https://pqmayo.org/assets/specs/mayo.pdf">MAYO Specification Document</a></li>
 *   <li><a href="https://github.com/PQCMayo/MAYO-C">MAYO Reference Implementation (C)</a></li>
 * </ul>
 */
public class MayoSigner
    implements MessageSigner
{
    private SecureRandom random;
    private MayoParameters params;
    private MayoPublicKeyParameters pubKey;
    private MayoPrivateKeyParameters privKey;

    /**
     * Initializes the signer for either signature generation or verification.
     *
     * @param forSigning {@code true} for signing mode, {@code false} for verification
     * @param param      CipherParameters containing:
     *                   <ul>
     *                     <li>{@link ParametersWithRandom} with {@link MayoPrivateKeyParameters} (for signing)</li>
     *                     <li>{@link MayoPublicKeyParameters} (for verification)</li>
     *                   </ul>
     * @throws IllegalArgumentException if invalid parameters are provided
     */
    @Override
    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (MayoPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (MayoPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (MayoPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
    }

    /**
     * Generates a MAYO signature for the given message using the initialized private key.
     * Follows the signature generation process outlined in the MAYO specification document.
     *
     * @param message The message to be signed
     * @return The signature bytes concatenated with the original message
     * @see <a href="https://pqmayo.org/assets/specs/mayo.pdf">MAYO Spec Algorithm 8 and 10</a>
     */
    @Override
    public byte[] generateSignature(byte[] message)
    {
        int k = params.getK();
        int v = params.getV();
        int o = params.getO();
        int n = params.getN();
        int m = params.getM();
        int vbytes = params.getVBytes();
        int oBytes = params.getOBytes();
        int saltBytes = params.getSaltBytes();
        int mVecLimbs = params.getMVecLimbs();
        int p1Limbs = params.getP1Limbs();
        int pk_seed_bytes = params.getPkSeedBytes();
        int digestBytes = params.getDigestBytes();
        int skSeedBytes = params.getSkSeedBytes();
        byte[] tenc = new byte[params.getMBytes()];
        byte[] t = new byte[m];
        byte[] y = new byte[m];
        byte[] salt = new byte[saltBytes];
        byte[] V = new byte[k * vbytes + params.getRBytes()];
        byte[] Vdec = new byte[v * k];
        int ok = k * o;
        int nk = k * n;
        byte[] A = new byte[((m + 7) / 8 * 8) * (ok + 1)];
        byte[] x = new byte[nk];
        byte[] r = new byte[ok + 1];
        byte[] s = new byte[nk];
        byte[] tmp = new byte[digestBytes + saltBytes + skSeedBytes + 1];
        byte[] sig = new byte[params.getSigBytes()];
        long[] P = new long[p1Limbs + params.getP2Limbs()];
        byte[] O = new byte[v * o];
        long[] Mtmp = new long[ok * mVecLimbs];
        long[] vPv = new long[k * k * mVecLimbs];
        SHAKEDigest shake = new SHAKEDigest(256);
        try
        {
            byte[] seed_sk = privKey.getSeedSk();
            // Expand secret key
            //MayoEngine.mayoExpandSk(params, seed_sk, P, O);
            int totalS = pk_seed_bytes + oBytes;
            byte[] seed_pk = new byte[totalS];

            // Generate S = seed_pk || (additional bytes), using SHAKE256.
            // Output length is param_pk_seed_bytes + param_O_bytes.
            shake.update(seed_sk, 0, seed_sk.length);
            shake.doFinal(seed_pk, 0, totalS);

            // Decode the portion of S after the first param_pk_seed_bytes into O.
            // (In C, this is: decode(S + param_pk_seed_bytes, O, param_v * param_o))
            GF16.decode(seed_pk, pk_seed_bytes, O, 0, O.length);

            // Expand P1 and P2 into the long array P using seed_pk.
            Utils.expandP1P2(params, P, seed_pk);

            // Compute L_i = (P1 + P1^t)*O + P2.
            // Here, we assume that P1P1tTimesO writes into the portion of P starting at offsetP2.
            //MayoEngine.P1P1tTimesO(params, P, O, P, p1Limbs);
            int bsMatEntriesUsed = 0;
            int omVecLimbs = o * mVecLimbs;
            for (int i = 0, io = 0, iomVecLimbs = 0; i < v; i++, io += o, iomVecLimbs += omVecLimbs)
            {
                for (int c = i, co = io, comVecLimbs = iomVecLimbs; c < v; c++, co += o, comVecLimbs += omVecLimbs)
                {
                    if (c == i)
                    {
                        bsMatEntriesUsed += mVecLimbs;
                        continue;
                    }
                    for (int j = 0, jmVecLimbs = p1Limbs; j < o; j++, jmVecLimbs += mVecLimbs)
                    {
                        // Multiply the m-vector at P1 for the current matrix entry,
                        // and accumulate into acc for row r.
                        GF16Utils.mVecMulAdd(mVecLimbs, P, bsMatEntriesUsed, O[co + j], P, iomVecLimbs + jmVecLimbs);
                        // Similarly, accumulate into acc for row c.
                        GF16Utils.mVecMulAdd(mVecLimbs, P, bsMatEntriesUsed, O[io + j], P, comVecLimbs + jmVecLimbs);
                    }
                    bsMatEntriesUsed += mVecLimbs;
                }
            }
            // Securely clear sensitive temporary data.
            Arrays.fill(seed_pk, (byte)0);

            // Hash message
            shake.update(message, 0, message.length);
            shake.doFinal(tmp, 0, digestBytes);

            // Generate random salt
            random.nextBytes(salt);

            System.arraycopy(salt, 0, tmp, digestBytes, salt.length);

            // Hash to salt
            System.arraycopy(seed_sk, 0, tmp, digestBytes + saltBytes, skSeedBytes);

            shake.update(tmp, 0, digestBytes + saltBytes + skSeedBytes);
            shake.doFinal(salt, 0, saltBytes);

            // Hash to t
            System.arraycopy(salt, 0, tmp, digestBytes, saltBytes);
            shake.update(tmp, 0, digestBytes + saltBytes);
            shake.doFinal(tenc, 0, params.getMBytes());
            GF16.decode(tenc, t, m);
            int size = v * k * mVecLimbs;
            long[] Pv = new long[size];
            byte[] Ox = new byte[v];
            for (int ctr = 0; ctr <= 255; ctr++)
            {
                tmp[tmp.length - 1] = (byte)ctr;

                // Generate V
                shake.update(tmp, 0, tmp.length);
                shake.doFinal(V, 0, V.length);

                // Decode vectors
                for (int i = 0; i < k; i++)
                {
                    GF16.decode(V, i * vbytes, Vdec, i * v, v);
                }

                //computeMandVPV(params, Vdec, P, params.getP1Limbs(), P, Mtmp, vPv);
                // Compute VL: VL = Vdec * L
                GF16Utils.mulAddMatXMMat(mVecLimbs, Vdec, P, p1Limbs, Mtmp, k, v, o);

                // Compute VP1V:
                // Allocate temporary array for Pv. Its length is V_MAX * K_MAX * M_VEC_LIMBS_MAX.
                // Compute Pv = P1 * V^T (using upper triangular multiplication)
                GF16Utils.mulAddMUpperTriangularMatXMatTrans(mVecLimbs, P, Vdec, Pv, v, k);
                // Compute VP1V = Vdec * Pv
                GF16Utils.mulAddMatXMMat(mVecLimbs, Vdec, Pv, vPv, k, v);

                computeRHS(vPv, t, y);
                computeA(Mtmp, A);

                // Clear trailing bytes
//                for (int i = 0; i < m; ++i)
//                {
//                    A[(i + 1) * (ok + 1) - 1] = 0;
//                }

                GF16.decode(V, k * vbytes, r, 0, ok);

                if (sampleSolution(A, y, r, x))
                {
                    break;
                }
                else
                {
                    Arrays.fill(Mtmp, 0L);
                    Arrays.fill(vPv, 0L);
                }
            }

            // Compute final signature components

            for (int i = 0, io = 0, in = 0, iv = 0; i < k; i++, io += o, in += n, iv += v)
            {
                GF16Utils.matMul(O, x, io, Ox, o, v);
                Bytes.xor(v, Vdec, iv, Ox, s, in);
                System.arraycopy(x, io, s, in + v, o);
            }

            // Encode and add salt
            GF16.encode(s, sig, nk);
            System.arraycopy(salt, 0, sig, sig.length - saltBytes, saltBytes);

            return Arrays.concatenate(sig, message);
        }
        finally
        {
            // Secure cleanup
            Arrays.fill(tenc, (byte)0);
            Arrays.fill(t, (byte)0);
            Arrays.fill(y, (byte)0);
            Arrays.fill(salt, (byte)0);
            Arrays.fill(V, (byte)0);
            Arrays.fill(Vdec, (byte)0);
            Arrays.fill(A, (byte)0);
            Arrays.fill(x, (byte)0);
            Arrays.fill(r, (byte)0);
            Arrays.fill(s, (byte)0);
            Arrays.fill(tmp, (byte)0);
        }
    }

    /**
     * Verifies a MAYO signature against the initialized public key and message.
     * Implements the verification process specified in the MAYO documentation.
     *
     * @param message   The original message
     * @param signature The signature to verify
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @see <a href="https://pqmayo.org/assets/specs/mayo.pdf">MAYO Spec Algorithm 9 and 11</a>
     */
    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        final int m = params.getM();
        final int n = params.getN();
        final int k = params.getK();
        int kn = k * n;
        int p1Limbs = params.getP1Limbs();
        int p2Limbs = params.getP2Limbs();
        int p3Limbs = params.getP3Limbs();
        final int mBytes = params.getMBytes();
        final int sigBytes = params.getSigBytes();
        final int digestBytes = params.getDigestBytes();
        final int saltBytes = params.getSaltBytes();
        int mVecLimbs = params.getMVecLimbs();
        byte[] tEnc = new byte[mBytes];
        byte[] t = new byte[m];
        byte[] y = new byte[m << 1];
        byte[] s = new byte[kn];
        long[] pk = new long[p1Limbs + p2Limbs + p3Limbs];
        byte[] tmp = new byte[digestBytes + saltBytes];
        byte[] cpk = pubKey.getEncoded();

        // Expand public key
        // mayo_expand_pk
        Utils.expandP1P2(params, pk, cpk);
        Utils.unpackMVecs(cpk, params.getPkSeedBytes(), pk, p1Limbs + p2Limbs, p3Limbs / mVecLimbs, m);

        // Hash message
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(message, 0, message.length);
        shake.doFinal(tmp, 0, digestBytes);

        // Compute t
        shake.update(tmp, 0, digestBytes);
        shake.update(signature, sigBytes - saltBytes, saltBytes);
        shake.doFinal(tEnc, 0, mBytes);
        GF16.decode(tEnc, t, m);

        // Decode signature
        GF16.decode(signature, s, kn);

        // Evaluate public map
        //evalPublicMap(params, s, P1, P2, P3, y);
        long[] SPS = new long[k * k * mVecLimbs];
        long[] PS = new long[kn * mVecLimbs];
        mayoGenericMCalculatePS(params, pk, p1Limbs, p1Limbs + p2Limbs, s, params.getV(), params.getO(), k, PS);
        mayoGenericMCalculateSPS(PS, s, mVecLimbs, k, n, SPS);
        byte[] zero = new byte[m];
        computeRHS(SPS, zero, y);

        // Compare results
        return Arrays.constantTimeAreEqual(m, y, 0, t, 0);
    }

    void computeRHS(long[] vPv, byte[] t, byte[] y)
    {
        final int m = params.getM();
        final int mVecLimbs = params.getMVecLimbs();
        final int k = params.getK();
        final int[] fTail = params.getFTail();

        final int topPos = ((m - 1) & 15) << 2;

        // Zero out tails of m_vecs if necessary
        if ((m & 15) != 0)
        {
            long mask = (1L << ((m & 15) << 2)) - 1;
            final int kSquared = k * k;

            for (int i = 0, index = mVecLimbs - 1; i < kSquared; i++, index += mVecLimbs)
            {
                vPv[index] &= mask;
            }
        }

        long[] temp = new long[mVecLimbs];
        byte[] tempBytes = new byte[mVecLimbs << 3];
        int kmVecLimbs = k * mVecLimbs;

        for (int i = k - 1, imVecLimbs = i * mVecLimbs, ikmVecLimbs = imVecLimbs * k; i >= 0; i--,
            imVecLimbs -= mVecLimbs, ikmVecLimbs -= kmVecLimbs)
        {
            for (int j = i, jmVecLimbs = imVecLimbs, jkmVecLimbs = ikmVecLimbs; j < k; j++,
                jmVecLimbs += mVecLimbs, jkmVecLimbs += kmVecLimbs)
            {
                // Multiply by X (shift up 4 bits)
                int top = (int)((temp[mVecLimbs - 1] >>> topPos) & 0xF);
                temp[mVecLimbs - 1] <<= 4;

                for (int limb = mVecLimbs - 2; limb >= 0; limb--)
                {
                    temp[limb + 1] ^= temp[limb] >>> 60;
                    temp[limb] <<= 4;
                }
                Pack.longToLittleEndian(temp, tempBytes, 0);

                // Reduce mod f(X)
                for (int jj = 0; jj < 4; jj++)
                {
                    int ft = fTail[jj];
                    if (ft == 0)
                    {
                        continue;
                    }

                    long product = GF16.mul(top, ft);
                    if ((jj & 1) == 0)
                    {
                        tempBytes[jj >> 1] ^= (byte)(product & 0xF);
                    }
                    else
                    {
                        tempBytes[jj >> 1] ^= (byte)((product & 0xF) << 4);
                    }
                }
                Pack.littleEndianToLong(tempBytes, 0, temp);

                // Extract from vPv and add
                int matrixIndex = ikmVecLimbs + jmVecLimbs;
                int symmetricIndex = jkmVecLimbs + imVecLimbs;
                boolean isDiagonal = (i == j);

                for (int limb = 0; limb < mVecLimbs; limb++)
                {
                    long value = vPv[matrixIndex + limb];
                    if (!isDiagonal)
                    {
                        value ^= vPv[symmetricIndex + limb];
                    }
                    temp[limb] ^= value;
                }
            }
        }
        Pack.longToLittleEndian(temp, tempBytes, 0);
        // Compute y
        for (int i = 0; i < m; i += 2)
        {
            int bytePos = i >> 1;
            y[i] = (byte)(t[i] ^ (tempBytes[bytePos] & 0xF));
            y[i + 1] = (byte)(t[i + 1] ^ ((tempBytes[bytePos] >>> 4) & 0xF));
        }
    }

    private static final int F_TAIL_LEN = 4;
    private static final long EVEN_BYTES = 0x00FF00FF00FF00FFL;
    private static final long EVEN_2BYTES = 0x0000FFFF0000FFFFL;

    void computeA(long[] Mtmp, byte[] AOut)
    {
        final int k = params.getK();
        final int o = params.getO();
        final int m = params.getM();
        final int mVecLimbs = params.getMVecLimbs();
        final int ACols = params.getACols();
        final int[] fTailArr = params.getFTail();

        int bitsToShift = 0;
        int wordsToShift = 0;
        final int MAYO_M_OVER_8 = (m + 7) >>> 3;
        int ok = o * k;
        int omVecLimbs = o * mVecLimbs;
        final int AWidth = ((ok + 15) >> 4) << 4;
        long[] A = new long[(AWidth * MAYO_M_OVER_8) << 4];

        // Zero out tails of m_vecs if necessary
        if ((m & 15) != 0)
        {
            long mask = 1L << ((m & 15) << 2);
            mask -= 1;
            for (int i = 0, idx = mVecLimbs - 1; i < ok; i++, idx += mVecLimbs)
            {
                Mtmp[idx] &= mask;
            }
        }

        for (int i = 0, io = 0, iomVecLimbs = 0; i < k; i++, io += o, iomVecLimbs += omVecLimbs)
        {
            for (int j = k - 1, jomVecLimbs = j * omVecLimbs, jo = j * o; j >= i; j--, jomVecLimbs -= omVecLimbs, jo -= o)
            {
                // Process Mj
                for (int c = 0, cmVecLimbs = 0; c < o; c++, cmVecLimbs += mVecLimbs)
                {
                    for (int limb = 0, limbAWidhth = 0; limb < mVecLimbs; limb++, limbAWidhth += AWidth)
                    {
                        long value = Mtmp[jomVecLimbs + limb + cmVecLimbs];

                        int aIndex = io + c + wordsToShift + limbAWidhth;
                        A[aIndex] ^= value << bitsToShift;

                        if (bitsToShift > 0)
                        {
                            A[aIndex + AWidth] ^= value >>> (64 - bitsToShift);
                        }
                    }
                }

                if (i != j)
                {
                    // Process Mi
                    for (int c = 0, cmVecLimbs = 0; c < o; c++, cmVecLimbs += mVecLimbs)
                    {
                        for (int limb = 0, limbAWidhth = 0; limb < mVecLimbs; limb++, limbAWidhth += AWidth)
                        {
                            long value = Mtmp[iomVecLimbs + limb + cmVecLimbs];
                            int aIndex = jo + c + wordsToShift + limbAWidhth;
                            A[aIndex] ^= value << bitsToShift;

                            if (bitsToShift > 0)
                            {
                                A[aIndex + AWidth] ^= value >>> (64 - bitsToShift);
                            }
                        }
                    }
                }

                bitsToShift += 4;
                if (bitsToShift == 64)
                {
                    wordsToShift += AWidth;
                    bitsToShift = 0;
                }
            }
        }

        // Transpose blocks
        for (int c = 0; c < AWidth * ((m + (((k + 1) * k) >> 1) + 15) >>> 4); c += 16)
        {
            transpose16x16Nibbles(A, c);
        }

        // Generate tab array
        byte[] tab = new byte[F_TAIL_LEN << 2];
        for (int i = 0, idx = 0; i < F_TAIL_LEN; i++)
        {
            int ft = fTailArr[i];
            tab[idx++] = (byte)GF16.mul(ft, 1);
            tab[idx++] = (byte)GF16.mul(ft, 2);
            tab[idx++] = (byte)GF16.mul(ft, 4);
            tab[idx++] = (byte)GF16.mul(ft, 8);
        }

        // Final processing
        for (int c = 0; c < AWidth; c += 16)
        {
            for (int r = m; r < m + (((k + 1) * k) >>> 1); r++)
            {
                int pos = (r >>> 4) * AWidth + c + (r & 15);
                long t0 = A[pos] & GF16Utils.MASK_LSB;
                long t1 = (A[pos] >>> 1) & GF16Utils.MASK_LSB;
                long t2 = (A[pos] >>> 2) & GF16Utils.MASK_LSB;
                long t3 = (A[pos] >>> 3) & GF16Utils.MASK_LSB;

                for (int t = 0, t4 = 0; t < F_TAIL_LEN; t++, t4 += 4)
                {
                    int targetRow = r + t - m;
                    int targetPos = (targetRow >> 4) * AWidth + c + (targetRow & 15);
                    A[targetPos] ^= (t0 * tab[t4]) ^ (t1 * tab[t4 + 1])
                        ^ (t2 * tab[t4 + 2]) ^ (t3 * tab[t4 + 3]);
                }
            }
        }

        byte[] Abytes = Pack.longToLittleEndian(A);
        // Decode to output
        for (int r = 0; r < m; r += 16)
        {
            for (int c = 0; c < ACols - 1; c += 16)
            {
                for (int i = 0; i + r < m; i++)
                {
                    GF16.decode(Abytes, (((r * AWidth) >> 4) + c + i) << 3,
                        AOut, (r + i) * ACols + c, Math.min(16, ACols - 1 - c));
                }
            }
        }
    }

    private static void transpose16x16Nibbles(long[] M, int offset)
    {
        for (int i = 0; i < 16; i += 2)
        {
            int idx1 = offset + i;
            int idx2 = idx1 + 1;
            long t = ((M[idx1] >>> 4) ^ M[idx2]) & 0x0F0F0F0F0F0F0F0FL;
            M[idx1] ^= t << 4;
            M[idx2] ^= t;
        }

        for (int i = 0, base = offset; i < 16; i += 4)
        {
            long t0 = ((M[base] >>> 8) ^ M[base + 2]) & EVEN_BYTES;
            long t1 = ((M[base + 1] >>> 8) ^ M[base + 3]) & EVEN_BYTES;
            M[base++] ^= t0 << 8;
            M[base++] ^= t1 << 8;
            M[base++] ^= t0;
            M[base++] ^= t1;
        }

        for (int i = 0; i < 4; i++)
        {
            int base = offset + i;
            long t0 = ((M[base] >>> 16) ^ M[base + 4]) & EVEN_2BYTES;
            long t1 = ((M[base + 8] >>> 16) ^ M[base + 12]) & EVEN_2BYTES;
            M[base] ^= t0 << 16;
            M[base + 8] ^= t1 << 16;
            M[base + 4] ^= t0;
            M[base + 12] ^= t1;
        }

        for (int i = 0; i < 8; i++)
        {
            int base = offset + i;
            long t = ((M[base] >>> 32) ^ M[base + 8]) & 0x00000000FFFFFFFFL;
            M[base] ^= t << 32;
            M[base + 8] ^= t;
        }
    }

    /**
     * Samples a solution for the MAYO signature equation using the provided parameters.
     *
     * @param A Coefficient matrix
     * @param y Target vector
     * @param r Randomness vector
     * @param x Output solution vector
     * @return {@code true} if a valid solution was found, {@code false} otherwise
     * @see <a href="https://pqmayo.org/assets/specs/mayo.pdf">MAYO Spec Algorithm 2</a>
     */
    boolean sampleSolution(byte[] A, byte[] y, byte[] r, byte[] x)
    {
        final int k = params.getK();
        final int o = params.getO();
        final int m = params.getM();
        final int aCols = params.getACols();
        int ok = k * o;
        // Initialize x with r values
        System.arraycopy(r, 0, x, 0, ok);

        // Compute Ar matrix product
        byte[] Ar = new byte[m];

        // Clear last column of A
//        for (int i = 0; i < m; i++)
//        {
//            A[ok + i * (ok + 1)] = 0;
//        }
        GF16Utils.matMul(A, r, 0, Ar, ok + 1, m);

        // Update last column of A with y - Ar
        for (int i = 0, idx = ok; i < m; i++, idx += ok + 1)
        {
            A[idx] = (byte)(y[i] ^ Ar[i]);
        }

        // Perform row echelon form transformation
        ef(A, m, aCols);

        // Check matrix rank
        boolean fullRank = false;
        for (int i = 0, idx = (m - 1) * aCols; i < aCols - 1; i++, idx++)
        {
            fullRank |= (A[idx] != 0);
        }
        if (!fullRank)
        {
            return false;
        }

        // Constant-time back substitution
        for (int row = m - 1, rowAcols = row * aCols; row >= 0; row--, rowAcols -= aCols)
        {
            byte finished = 0;
            int colUpperBound = Math.min(row + (32 / (m - row)), ok);

            for (int col = row; col <= colUpperBound; col++)
            {
                byte correctCol = (byte)((-(A[rowAcols + col] & 0xFF)) >> 31);

                // Update x[col] using constant-time mask
                byte u = (byte)(correctCol & ~finished & A[rowAcols + aCols - 1]);
                x[col] ^= u;

                // Update matrix entries
                for (int i = 0, iaCols_col = col, iaCols_aCols1 = aCols - 1; i < row; i += 8,
                    iaCols_col += aCols << 3, iaCols_aCols1 += aCols << 3)
                {
                    long tmp = 0;
                    // Pack 8 GF(16) elements into long
                    for (int j = 0, jaCols = 0; j < 8; j++, jaCols += aCols)
                    {
                        tmp ^= (long)(A[iaCols_col + jaCols] & 0xFF) << (j << 3);
                    }

                    // GF(16) multiplication
                    tmp = GF16Utils.mulFx8(u, tmp);

                    // Unpack and update
                    for (int j = 0, jaCols = 0; j < 8; j++, jaCols += aCols)
                    {
                        A[iaCols_aCols1 + jaCols] ^= (byte)((tmp >> (j << 3)) & 0x0F);
                    }
                }
                finished |= correctCol;
            }
        }
        return true;
    }

    /**
     * Converts a matrix A (given as a flat array of GF(16) elements, one per byte)
     * into row echelon form (with ones on the first nonzero entries) in constant time.
     *
     * @param A     the input matrix, stored rowwise; each element is in [0,15]
     * @param nrows the number of rows
     * @param ncols the number of columns (GF(16) elements per row)
     * @see <a href="https://pqmayo.org/assets/specs/mayo.pdf">MAYO Spec Algorithm 1</a>
     */
    void ef(byte[] A, int nrows, int ncols)
    {
        // Each 64-bit long can hold 16 nibbles (16 GF(16) elements).
        int rowLen = (ncols + 15) >> 4;

        // Allocate temporary arrays.
        long[] pivotRow = new long[rowLen];
        long[] pivotRow2 = new long[rowLen];
        // The packed matrix: one contiguous array storing nrows rows, each rowLen longs long.
        long[] packedA = new long[nrows * rowLen];
        int len = params.getO() * params.getK() + 16;
        byte[] bytes = new byte[len >> 1];
        int len_4 = len >> 4;

        // Pack the matrix rows.
        for (int i = 0, incols = 0, irowLen = 0; i < nrows; i++, incols += ncols, irowLen += rowLen)
        {
            //packRow(A, i, ncols);
            // Process each 64-bit word (each holds 16 nibbles).
            for (int word = 0; word < rowLen; word++)
            {
                long wordVal = 0;
                for (int nibble = 0; nibble < 16; nibble++)
                {
                    int col = (word << 4) + nibble;
                    if (col < ncols)
                    {
                        wordVal |= ((long)A[incols + col] & 0xF) << (nibble << 2);
                    }
                }
                packedA[word + irowLen] = wordVal;
            }
        }

        int pivotRowIndex = 0;
        // Loop over each pivot column (each column corresponds to one GF(16) element)
        for (int pivotCol = 0; pivotCol < ncols; pivotCol++)
        {
            int lowerBound = Math.max(0, pivotCol + nrows - ncols);
            int upperBound = Math.min(nrows - 1, pivotCol);

            // Zero out pivot row buffers.
            Arrays.clear(pivotRow);
            Arrays.clear(pivotRow2);

            // Try to select a pivot row in constant time.
            int pivot = 0;
            long pivotIsZero = -1L; // all bits set (0xFFFFFFFFFFFFFFFF)
            int searchUpper = Math.min(nrows - 1, upperBound + 32);
            for (int row = lowerBound, rowRowLen = lowerBound * rowLen; row <= searchUpper; row++, rowRowLen += rowLen)
            {
                long isPivotRow = ~ctCompare64(row, pivotRowIndex);
                //ct64IsGreaterThan(a, b): Returns 0xFFFFFFFFFFFFFFFF if a > b, 0 otherwise.
                long belowPivotRow = ((long)pivotRowIndex - (long)row) >> 63;
                for (int j = 0; j < rowLen; j++)
                {
                    // The expression below accumulates (in constant time) the candidate pivot row.
                    pivotRow[j] ^= (isPivotRow | (belowPivotRow & pivotIsZero)) & packedA[rowRowLen + j];
                }
                // Extract candidate pivot element from the packed row.
                pivot = (int)((pivotRow[pivotCol >>> 4] >>> ((pivotCol & 15) << 2)) & 0xF);
                pivotIsZero = ~((-(long)pivot) >> 63);
            }

            // Multiply the pivot row by the inverse of the pivot element.
            vecMulAddU64(rowLen, pivotRow, GF16.inv((byte)pivot), pivotRow2);

            // Conditionally write the pivot row back into the correct row (if pivot is nonzero).
            for (int row = lowerBound, rowRowLen = lowerBound * rowLen; row <= upperBound; row++, rowRowLen += rowLen)
            {
                long doCopy = ~ctCompare64(row, pivotRowIndex) & ~pivotIsZero;
                long doNotCopy = ~doCopy;
                for (int col = 0, rowRowLen_col = rowRowLen; col < rowLen; col++, rowRowLen_col++)
                {
                    // Since the masks are disjoint, addition is equivalent to OR.
                    packedA[rowRowLen_col] = (doNotCopy & packedA[rowRowLen_col]) | (doCopy & pivotRow2[col]);
                }
            }

            // Eliminate entries below the pivot.
            for (int row = lowerBound, rowRowLen = lowerBound * rowLen; row < nrows; row++, rowRowLen += rowLen)
            {
                int belowPivot = (row > pivotRowIndex) ? -1 : 0;
                //int eltToElim = mExtractElementFromPacked(packedA, row, rowLen, pivotCol);
                int eltToElim = (int)((packedA[rowRowLen + (pivotCol >>> 4)] >>> ((pivotCol & 15) << 2)) & 0xF);
                vecMulAddU64(rowLen, pivotRow2, (byte)(belowPivot & eltToElim), packedA, rowRowLen);
            }

            // If pivot is nonzero, increment pivotRowIndex.
            if (pivot != 0)
            {
                pivotRowIndex++;
            }
        }

        int outIndex = 0;
        // At this point, packedA holds the row-echelon form of the original matrix.
        // (Depending on your application you might want to unpack it back to A.)
        for (int i = 0, irowLen = 0; i < nrows; i++, irowLen += rowLen)
        {
            Pack.longToLittleEndian(packedA, irowLen, len_4, bytes, 0);
            GF16.decode(bytes, 0, A, outIndex, ncols);
            outIndex += ncols;
        }
    }

    /**
     * Constant-time comparison: returns 0 if a==b, else returns all 1s (0xFFFFFFFFFFFFFFFF).
     */
    private static long ctCompare64(int a, int b)
    {
        // Compute (-(a XOR b)) >> 63 then XOR with UINT64_BLOCKER.
        return (-(long)(a ^ b)) >> 63;
    }

    /**
     * Multiplies each word of the input vector (in) by a GF(16) scalar (a),
     * then XORs the result into the accumulator vector (acc).
     * <p>
     * This version updates the acc array starting at index 0.
     *
     * @param legs the number of 64-bit words in the vector.
     * @param in   the input vector.
     * @param a    the GF(16) scalar (as a byte; only low 4 bits used).
     * @param acc  the accumulator vector which is updated.
     */
    private static void vecMulAddU64(int legs, long[] in, byte a, long[] acc)
    {
        int tab = mulTable(a & 0xFF);
        for (int i = 0; i < legs; i++)
        {
            long val = ((in[i] & GF16Utils.MASK_LSB) * (tab & 0xFF))
                ^ (((in[i] >>> 1) & GF16Utils.MASK_LSB) * ((tab >>> 8) & 0xF))
                ^ (((in[i] >>> 2) & GF16Utils.MASK_LSB) * ((tab >>> 16) & 0xF))
                ^ (((in[i] >>> 3) & GF16Utils.MASK_LSB) * ((tab >>> 24) & 0xF));
            acc[i] ^= val;
        }
    }

    /**
     * Overloaded version of vecMulAddU64 that writes to acc starting at accOffset.
     *
     * @param legs      the number of 64-bit words.
     * @param in        the input vector.
     * @param a         the GF(16) scalar.
     * @param acc       the accumulator vector.
     * @param accOffset the starting index in acc.
     */
    private static void vecMulAddU64(int legs, long[] in, byte a, long[] acc, int accOffset)
    {
        int tab = mulTable(a & 0xFF);
        for (int i = 0; i < legs; i++)
        {
            long val = ((in[i] & GF16Utils.MASK_LSB) * (tab & 0xFF))
                ^ (((in[i] >>> 1) & GF16Utils.MASK_LSB) * ((tab >>> 8) & 0xF))
                ^ (((in[i] >>> 2) & GF16Utils.MASK_LSB) * ((tab >>> 16) & 0xF))
                ^ (((in[i] >>> 3) & GF16Utils.MASK_LSB) * ((tab >>> 24) & 0xF));
            acc[accOffset + i] ^= val;
        }
    }

    /**
     * Computes a multiplication table for nibble-packed vectors.
     * <p>
     * Implements arithmetic for GF(16) elements modulo (x^4 + x + 1).
     *
     * @param b a GF(16) element (only lower 4 bits are used)
     * @return a 32-bit integer representing the multiplication table.
     */
    private static int mulTable(int b)
    {
        int x = b * 0x08040201;
        int highHalf = x & 0xf0f0f0f0;
        return x ^ (highHalf >>> 4) ^ (highHalf >>> 3);
    }

    private static void mayoGenericMCalculatePS(MayoParameters p, long[] P1, int p2, int p3, byte[] S,
                                                int v, int o, int k, long[] PS)
    {
        int n = o + v;
        int mVecLimbs = p.getMVecLimbs();
        long[] accumulator = new long[(mVecLimbs * p.getK() * p.getN() * mVecLimbs) << 4];
        int o_mVecLimbs = o * mVecLimbs;
        int pUsed = 0;
        for (int row = 0, krow = 0, orow_mVecLimbs = 0; row < v; row++, krow += k, orow_mVecLimbs += o_mVecLimbs)
        {
            for (int j = row; j < v; j++)
            {
                for (int col = 0, ncol = 0; col < k; col++, ncol += n)
                {
                    Longs.xorTo(mVecLimbs, P1, pUsed, accumulator, (((krow + col) << 4) + (S[ncol + j] & 0xFF)) * mVecLimbs);
                }
                pUsed += mVecLimbs;
            }

            for (int j = 0, orow_j_mVecLimbs = orow_mVecLimbs; j < o; j++, orow_j_mVecLimbs += mVecLimbs)
            {
                for (int col = 0, ncol = 0; col < k; col++, ncol += n)
                {
                    Longs.xorTo(mVecLimbs, P1, p2 + orow_j_mVecLimbs, accumulator, (((krow + col) << 4) + (S[ncol + j + v] & 0xFF)) * mVecLimbs);
                }
            }
        }

        pUsed = 0;
        for (int row = v, krow = v * k; row < n; row++, krow += k)
        {
            for (int j = row; j < n; j++)
            {
                for (int col = 0, ncol = 0; col < k; col++, ncol += n)
                {
                    Longs.xorTo(mVecLimbs, P1, p3 + pUsed, accumulator, (((krow + col) << 4) + (S[ncol + j] & 0xFF)) * mVecLimbs);
                }
                pUsed += mVecLimbs;
            }
        }

        mVecMultiplyBins(mVecLimbs, n * k, accumulator, PS);
    }

    private static void mayoGenericMCalculateSPS(long[] PS, byte[] S, int mVecLimbs, int k, int n, long[] SPS)
    {
        int kk = k * k;
        final int accumulatorSize = (mVecLimbs * kk) << 4;
        final long[] accumulator = new long[accumulatorSize];
        int kmVecLimbs = k * mVecLimbs;

        // Accumulation phase
        for (int row = 0, nrow = 0, krowmVecLimbs16 = 0; row < k; row++, nrow += n, krowmVecLimbs16 += kmVecLimbs << 4)
        {
            for (int j = 0, jkmVecLimbs = 0; j < n; j++, jkmVecLimbs += kmVecLimbs)
            {
                final int sValmVecLimbs = (S[nrow + j] & 0xFF) * mVecLimbs + krowmVecLimbs16; // Unsigned byte value
                for (int col = 0, colmVecLimbs = 0; col < k; col++, colmVecLimbs += mVecLimbs)
                {
                    Longs.xorTo(mVecLimbs, PS, jkmVecLimbs + colmVecLimbs, accumulator, sValmVecLimbs + (colmVecLimbs << 4));
                }
            }
        }

        // Processing phase
        mVecMultiplyBins(mVecLimbs, kk, accumulator, SPS);
    }

    private static void mVecMultiplyBins(int mVecLimbs, int len, long[] bins, long[] ps)
    {
        long a, b, t;
        int mVecLimbs2 = mVecLimbs + mVecLimbs,
            mVecLimbs3 = mVecLimbs2 + mVecLimbs,
            mVecLimbs4 = mVecLimbs3 + mVecLimbs,
            mVecLimbs5 = mVecLimbs4 + mVecLimbs,
            mVecLimbs6 = mVecLimbs5 + mVecLimbs,
            mVecLimbs7 = mVecLimbs6 + mVecLimbs,
            mVecLimbs8 = mVecLimbs7 + mVecLimbs,
            mVecLimbs9 = mVecLimbs8 + mVecLimbs,
            mVecLimbs10 = mVecLimbs9 + mVecLimbs,
            mVecLimbs11 = mVecLimbs10 + mVecLimbs,
            mVecLimbs12 = mVecLimbs11 + mVecLimbs,
            mVecLimbs13 = mVecLimbs12 + mVecLimbs,
            mVecLimbs14 = mVecLimbs13 + mVecLimbs,
            mVecLimbs15 = mVecLimbs14 + mVecLimbs;
        for (int i = 0, imVecLimbs4 = 0; i < len; i++, imVecLimbs4 += (mVecLimbs << 4))
        {
            for (int j = 0, off = imVecLimbs4; j < mVecLimbs; j++, off++)
            {
                b = bins[off + mVecLimbs5];
                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs10] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                a = bins[off + mVecLimbs11];
                t = (a & GF16Utils.MASK_MSB) >>> 3;
                a = bins[off + mVecLimbs12] ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);

                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs7] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                t = (a & GF16Utils.MASK_MSB) >>> 3;
                a = bins[off + mVecLimbs6] ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);

                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs14] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                t = (a & GF16Utils.MASK_MSB) >>> 3;
                a = bins[off + mVecLimbs3] ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);

                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs15] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                t = (a & GF16Utils.MASK_MSB) >>> 3;
                a = bins[off + mVecLimbs8] ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);

                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs13] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                t = (a & GF16Utils.MASK_MSB) >>> 3;
                a = bins[off + mVecLimbs4] ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);

                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs9] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                t = (a & GF16Utils.MASK_MSB) >>> 3;
                a = bins[off + mVecLimbs2] ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);

                t = b & GF16Utils.MASK_LSB;
                b = bins[off + mVecLimbs] ^ ((b & GF16Utils.NIBBLE_MASK_LSB) >>> 1) ^ ((t << 3) + t);

                t = (a & GF16Utils.MASK_MSB) >>> 3;
                ps[(imVecLimbs4 >> 4) + j] = b ^ ((a & GF16Utils.NIBBLE_MASK_MSB) << 1) ^ ((t << 1) + t);
            }
        }
    }
}
