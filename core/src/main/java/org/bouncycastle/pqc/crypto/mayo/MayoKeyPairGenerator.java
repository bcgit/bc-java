package org.bouncycastle.pqc.crypto.mayo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;

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
        // Retrieve parameters from p.
        int mVecLimbs = p.getMVecLimbs();
        int m = p.getM();
        int v = p.getV();
        int o = p.getO();
        int oBytes = p.getOBytes();
        int p1Limbs = p.getP1Limbs();
        int p3Limbs = p.getP3Limbs();
        int pkSeedBytes = p.getPkSeedBytes();
        int skSeedBytes = p.getSkSeedBytes();

        byte[] cpk = new byte[p.getCpkBytes()];
        // seed_sk points to csk.
        byte[] seed_sk = new byte[p.getCskBytes()];

        // Allocate S = new byte[PK_SEED_BYTES_MAX + O_BYTES_MAX]
        byte[] seed_pk = new byte[pkSeedBytes + oBytes];

        // Allocate P as a long array of size (P1_LIMBS_MAX + P2_LIMBS_MAX)
        long[] P = new long[p1Limbs + p.getP2Limbs()];

        // Allocate P3 as a long array of size (O_MAX * O_MAX * M_VEC_LIMBS_MAX), zero-initialized.
        long[] P3 = new long[o * o * mVecLimbs];

        byte[] O = new byte[v * o];

        // Generate secret key seed (seed_sk) using a secure random generator.
        random.nextBytes(seed_sk);

        // S ← shake256(seed_sk, pk_seed_bytes + O_bytes)
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed_sk, 0, skSeedBytes);
        shake.doFinal(seed_pk, 0, pkSeedBytes + oBytes);

        // o ← Decode_o(S[ param_pk_seed_bytes : param_pk_seed_bytes + O_bytes ])
        // Decode nibbles from S starting at offset param_pk_seed_bytes into O,
        // with expected output length = param_v * param_o.
        Utils.decode(seed_pk, pkSeedBytes, O, O.length);

        // Expand P1 and P2 into the array P using seed_pk.
        Utils.expandP1P2(p, P, seed_pk);

        // Compute P1 * O + P2 and store the result in P2.
        // GF16Utils.P1TimesO(p, P, O, P2);
        // Here, bsMatRows and bsMatCols are both paramV, and matCols is paramO, triangular=1.
        GF16Utils.mulAddMUpperTriangularMatXMat(mVecLimbs, P, O, P, p1Limbs, v, o);

        // Compute P3 = O^T * (P1*O + P2).
        // Here, treat P2 as the bsMat for the multiplication.
        // Dimensions: mat = O (size: paramV x paramO), bsMat = P2 (size: paramV x paramO),
        // and acc (P3) will have dimensions: (paramO x paramO), each entry being an m-vector.
        GF16Utils.mulAddMatTransXMMat(mVecLimbs, O, P, p1Limbs, P3, v, o, o);

        // Store seed_pk into the public key cpk.
        System.arraycopy(seed_pk, 0, cpk, 0, pkSeedBytes);

        // Allocate an array for the "upper" part of P3.
        long[] P3_upper = new long[p3Limbs];

        // Compute Upper(P3) and store the result in P3_upper.
        int mVecsStored = 0;
        int omVecLimbs = o * mVecLimbs;
        for (int r = 0, rmVecLimbs = 0, romVecLimbs = 0; r < o; r++, romVecLimbs += omVecLimbs, rmVecLimbs += mVecLimbs)
        {
            for (int c = r, cmVecLimbs = rmVecLimbs, comVecLimbs = romVecLimbs; c < o; c++, cmVecLimbs += mVecLimbs, comVecLimbs += omVecLimbs)
            {
                // Copy the vector at (r, c) into the output.
                System.arraycopy(P3, romVecLimbs + cmVecLimbs, P3_upper, mVecsStored, mVecLimbs);

                // If off-diagonal, add (XOR) the vector at (c, r) into the same output vector.
                if (r != c)
                {
                    Longs.xorTo(mVecLimbs, P3, comVecLimbs + rmVecLimbs, P3_upper, mVecsStored);
                }
                mVecsStored += mVecLimbs;
            }
        }

        // Pack the m-vectors in P3_upper into cpk (after the seed_pk).
        // The number of m-vectors to pack is (param_P3_limbs / m_vec_limbs),
        // and param_m is used as the m value.
        Utils.packMVecs(P3_upper, cpk, pkSeedBytes, p3Limbs / mVecLimbs, m);
        // Securely clear sensitive data.
        Arrays.clear(O);
        Arrays.clear(P3);

        return new AsymmetricCipherKeyPair(new MayoPublicKeyParameters(p, cpk), new MayoPrivateKeyParameters(p, seed_sk));
    }
}
