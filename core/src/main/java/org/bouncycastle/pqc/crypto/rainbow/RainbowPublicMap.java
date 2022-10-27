package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

class RainbowPublicMap
{
    private ComputeInField cf;
    private RainbowParameters params;
    private final int num_gf_elements = 256;

    public RainbowPublicMap(RainbowParameters params)
    {
        this.cf = new ComputeInField();
        this.params = params;
    }

    private short[][] compute_accumulator(short[] x, short[] y, short[][][] a, int dim)
    {
        short[][] accu = new short[num_gf_elements][dim];
        short[] tmp;

        if (y.length != a[0].length ||
            x.length != a[0][0].length ||
            a.length != dim)
        {
            throw new RuntimeException("Accumulator calculation not possible!");
        }

        for (int i = 0; i < y.length; i++)
        {
            tmp = cf.multVect(y[i], x);
            for (int j = 0; j < x.length; j++)
            {
                for (int k = 0; k < a.length; k++)
                {
                    int index = tmp[j];
                    if (index != 0)
                    {
                        accu[index][k] = GF2Field.addElem(accu[index][k], a[k][i][j]);
                    }
                }
            }
        }

        return accu;
    }

    private short[] add_and_reduce(short[][] accu)
    {
        int m = this.params.getM();
        short[] tmp;
        short[] ret = new short[m];

        for (int b = 0; b < 8; b++)
        {
            int accu_bit = (int)Math.pow(2, b);
            tmp = new short[m];
            for (int i = accu_bit; i < num_gf_elements; i += accu_bit * 2)
            {
                for (int j = 0; j < accu_bit; j++)
                {
                    tmp = cf.addVect(tmp, accu[i + j]);
                }
            }
            ret = cf.addVect(ret, cf.multVect((short)accu_bit, tmp));
        }

        return ret;
    }

    public short[] publicMap(RainbowPublicKeyParameters pk, short[] signature)
    {
        short[][] accu = compute_accumulator(signature, signature, pk.pk, params.getM());
        return add_and_reduce(accu);
    }

    public short[] publicMap_cyclic(RainbowPublicKeyParameters pk, short[] signature)
    {
        int v1 = params.getV1();
        int o1 = params.getO1();
        int o2 = params.getO2();
        short[][][] tmp;
        short[][] accu_l1;
        short[][] accu_l2;
        short[][] accu = new short[num_gf_elements][o1 + o2];

        short[] sig_v1 = Arrays.copyOfRange(signature, 0, v1);
        short[] sig_o1 = Arrays.copyOfRange(signature, v1, v1 + o1);
        short[] sig_o2 = Arrays.copyOfRange(signature, v1 + o1, signature.length);

        SecureRandom pk_random = new RainbowDRBG(pk.pk_seed, pk.getParameters().getHash_algo());

        // layer 1
        tmp = RainbowUtil.generate_random(pk_random, o1, v1, v1, true);    // l1_Q1
        accu_l1 = compute_accumulator(sig_v1, sig_v1, tmp, o1);
        tmp = RainbowUtil.generate_random(pk_random, o1, v1, o1, false);   // l1_Q2
        accu_l1 = cf.addMatrix(accu_l1, compute_accumulator(sig_o1, sig_v1, tmp, o1));
        accu_l1 = cf.addMatrix(accu_l1, compute_accumulator(sig_o2, sig_v1, pk.l1_Q3, o1));
        accu_l1 = cf.addMatrix(accu_l1, compute_accumulator(sig_o1, sig_o1, pk.l1_Q5, o1));
        accu_l1 = cf.addMatrix(accu_l1, compute_accumulator(sig_o2, sig_o1, pk.l1_Q6, o1));
        accu_l1 = cf.addMatrix(accu_l1, compute_accumulator(sig_o2, sig_o2, pk.l1_Q9, o1));

        // layer 2
        tmp = RainbowUtil.generate_random(pk_random, o2, v1, v1, true);    // l2_Q1
        accu_l2 = compute_accumulator(sig_v1, sig_v1, tmp, o2);
        tmp = RainbowUtil.generate_random(pk_random, o2, v1, o1, false);   // l2_Q2
        accu_l2 = cf.addMatrix(accu_l2, compute_accumulator(sig_o1, sig_v1, tmp, o2));
        tmp = RainbowUtil.generate_random(pk_random, o2, v1, o2, false);   // l2_Q3
        accu_l2 = cf.addMatrix(accu_l2, compute_accumulator(sig_o2, sig_v1, tmp, o2));
        tmp = RainbowUtil.generate_random(pk_random, o2, o1, o1, true);    // l2_Q5
        accu_l2 = cf.addMatrix(accu_l2, compute_accumulator(sig_o1, sig_o1, tmp, o2));
        tmp = RainbowUtil.generate_random(pk_random, o2, o1, o2, false);   // l2_Q6
        accu_l2 = cf.addMatrix(accu_l2, compute_accumulator(sig_o2, sig_o1, tmp, o2));
        accu_l2 = cf.addMatrix(accu_l2, compute_accumulator(sig_o2, sig_o2, pk.l2_Q9, o2));

        for (int i = 0; i < num_gf_elements; i++)
        {
            accu[i] = Arrays.concatenate(accu_l1[i], accu_l2[i]);
        }

        return add_and_reduce(accu);
    }

}
