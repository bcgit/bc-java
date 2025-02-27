package org.bouncycastle.pqc.crypto.mayo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.util.Pack;

public class MayoKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private MayoParameters p;
    private SecureRandom random;


    public void init(KeyGenerationParameters param)
    {
        this.p = ((MayoKeyGenerationParameters)param).getParameters();
        this.random = param.getRandom();
    }


    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int ret = MayoEngine.MAYO_OK;
        byte[] cpk = new byte[p.getCpkBytes()];
        // seed_sk points to csk.
        byte[] seed_sk = new byte[p.getCskBytes()];

        // Allocate S = new byte[PK_SEED_BYTES_MAX + O_BYTES_MAX]
        byte[] S = new byte[p.getPkSeedBytes() + p.getOBytes()];

        // Allocate P as a long array of size (P1_LIMBS_MAX + P2_LIMBS_MAX)
        long[] P = new long[p.getP1Limbs() + p.getP2Limbs()];

        // Allocate P3 as a long array of size (O_MAX * O_MAX * M_VEC_LIMBS_MAX), zero-initialized.
        long[] P3 = new long[p.getO() * p.getO() * p.getMVecLimbs()];

        // seed_pk will be a reference into S.
        byte[] seed_pk;

        // Allocate O as a byte array of size (V_MAX * O_MAX).
        // Here we assume V_MAX is given by p.getV() (or replace with a constant if needed).
        byte[] O = new byte[p.getV() * p.getO()];

        // Retrieve parameters from p.
        int m_vec_limbs = p.getMVecLimbs();
        int param_m = p.getM();
        int param_v = p.getV();
        int param_o = p.getO();
        int param_O_bytes = p.getOBytes();
        int param_P1_limbs = p.getP1Limbs();
        int param_P3_limbs = p.getP3Limbs();
        int param_pk_seed_bytes = p.getPkSeedBytes();
        int param_sk_seed_bytes = p.getSkSeedBytes();

        // In the C code, P1 is P and P2 is P offset by param_P1_limbs.
        // In Java, we will have functions (like expandP1P2) work on the full array P.

        // Generate secret key seed (seed_sk) using a secure random generator.
        random.nextBytes(seed_sk);

        // S ← shake256(seed_sk, pk_seed_bytes + O_bytes)
        Utils.shake256(S, param_pk_seed_bytes + param_O_bytes, seed_sk, param_sk_seed_bytes);

        // seed_pk is the beginning of S.
        seed_pk = S;

        // o ← Decode_o(S[ param_pk_seed_bytes : param_pk_seed_bytes + O_bytes ])
        // Decode nibbles from S starting at offset param_pk_seed_bytes into O,
        // with expected output length = param_v * param_o.
        Utils.decode(S, param_pk_seed_bytes, O, param_v * param_o);

        // Expand P1 and P2 into the array P using seed_pk.
        MayoEngine.expandP1P2(p, P, seed_pk);

        // For compute_P3, we need to separate P1 and P2.
        // Here, we treat P1 as the first param_P1_limbs elements of P,
        // and P2 as the remaining elements.
        long[] P1 = P;
        long[] P2 = new long[P.length - param_P1_limbs];
        System.arraycopy(P, param_P1_limbs, P2, 0, P2.length);

        // Compute P3, which (in the process) modifies P2.
        computeP3(p, P1, P2, O, P3);

        // Store seed_pk into the public key cpk.
        System.arraycopy(seed_pk, 0, cpk, 0, param_pk_seed_bytes);

        // Allocate an array for the "upper" part of P3.
        long[] P3_upper = new long[p.getP3Limbs()];

        // Compute Upper(P3) and store the result in P3_upper.
        mUpper(p, P3, P3_upper, param_o);

        // Pack the m-vectors in P3_upper into cpk (after the seed_pk).
        // The number of m-vectors to pack is (param_P3_limbs / m_vec_limbs),
        // and param_m is used as the m value.
        Utils.packMVecs(P3_upper, cpk, param_pk_seed_bytes, param_P3_limbs / m_vec_limbs, param_m);
        // Securely clear sensitive data.
//        secureClear(O);
//        secureClear(P2);
//        secureClear(P3);

        return new AsymmetricCipherKeyPair(new MayoPublicKeyParameter(p, cpk), new MayoPrivateKeyParameter(p, seed_sk));
    }

    /**
     * Computes P3 from P1, P2, and O.
     * <p>
     * In C, compute_P3 does:
     * 1. Compute P1*O + P2, storing result in P2.
     * 2. Compute P3 = O^T * (P1*O + P2).
     *
     * @param p  the parameter object.
     * @param P1 the P1 matrix as a long[] array.
     * @param P2 the P2 matrix as a long[] array; on output, P1*O is added to it.
     * @param O  the O matrix as a byte[] array.
     * @param P3 the output matrix (as a long[] array) which will receive O^T*(P1*O + P2).
     */
    public static void computeP3(MayoParameters p, long[] P1, long[] P2, byte[] O, long[] P3)
    {
        int mVecLimbs = p.getMVecLimbs();
        int paramV = p.getV();
        int paramO = p.getO();

        // Compute P1 * O + P2 and store the result in P2.
        GF16Utils.P1TimesO(p, P1, O, P2);

        // Compute P3 = O^T * (P1*O + P2).
        // Here, treat P2 as the bsMat for the multiplication.
        // Dimensions: mat = O (size: paramV x paramO), bsMat = P2 (size: paramV x paramO),
        // and acc (P3) will have dimensions: (paramO x paramO), each entry being an m-vector.
        GF16Utils.mulAddMatTransXMMat(mVecLimbs, O, P2, P3, paramV, paramO, paramO);
    }

    /**
     * Reproduces the behavior of the C function m_upper.
     * <p>
     * For each pair (r, c) with 0 <= r <= c < size, it copies the m-vector at
     * position (r, c) from 'in' to the next position in 'out' and, if r != c,
     * it adds (XORs) the m-vector at position (c, r) into that same output vector.
     *
     * @param p    the parameter object (used to get mVecLimbs)
     * @param in   the input long array (each vector is mVecLimbs in length)
     * @param out  the output long array (must be large enough to store all output vectors)
     * @param size the size parameter defining the matrix dimensions.
     */
    public static void mUpper(MayoParameters p, long[] in, long[] out, int size)
    {
        int mVecLimbs = p.getMVecLimbs();
        int mVecsStored = 0;
        for (int r = 0; r < size; r++)
        {
            for (int c = r; c < size; c++)
            {
                // Compute the starting index for the (r, c) vector in the input array.
                int srcOffset = mVecLimbs * (r * size + c);
                // Compute the output offset for the current stored vector.
                int destOffset = mVecLimbs * mVecsStored;

                // Copy the vector at (r, c) into the output.
                System.arraycopy(in, srcOffset, out, destOffset, mVecLimbs);

                // If off-diagonal, add (XOR) the vector at (c, r) into the same output vector.
                if (r != c)
                {
                    int srcOffset2 = mVecLimbs * (c * size + r);
                    GF16Utils.mVecAdd(mVecLimbs, in, srcOffset2, out, destOffset);
                }
                mVecsStored++;
            }
        }
    }
}
