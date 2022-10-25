package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.util.Arrays;

public class RainbowPrivateKeyParameters
    extends RainbowKeyParameters
{
    final byte[] sk_seed;
    final short[][] s1;
    final short[][] t1;
    final short[][] t3;
    final short[][] t4;
    final short[][][] l1_F1;
    final short[][][] l1_F2;
    final short[][][] l2_F1;
    final short[][][] l2_F2;
    final short[][][] l2_F3;
    final short[][][] l2_F5;
    final short[][][] l2_F6;

    public RainbowPrivateKeyParameters(RainbowParameters params,
                                       byte[] sk_seed, short[][] s1,
                                       short[][] t1, short[][] t3, short[][] t4,
                                       short[][][] l1_F1, short[][][] l1_F2,
                                       short[][][] l2_F1, short[][][] l2_F2,
                                       short[][][] l2_F3, short[][][] l2_F5, short[][][] l2_F6)
    {
        super(true, params);

        this.sk_seed = sk_seed.clone();
        this.s1 = RainbowUtil.cloneArray(s1);
        this.t1 = RainbowUtil.cloneArray(t1);
        this.t3 = RainbowUtil.cloneArray(t3);
        this.t4 = RainbowUtil.cloneArray(t4);
        this.l1_F1 = RainbowUtil.cloneArray(l1_F1);
        this.l1_F2 = RainbowUtil.cloneArray(l1_F2);
        this.l2_F1 = RainbowUtil.cloneArray(l2_F1);
        this.l2_F2 = RainbowUtil.cloneArray(l2_F2);
        this.l2_F3 = RainbowUtil.cloneArray(l2_F3);
        this.l2_F5 = RainbowUtil.cloneArray(l2_F5);
        this.l2_F6 = RainbowUtil.cloneArray(l2_F6);
    }

    public RainbowPrivateKeyParameters(RainbowParameters params, byte[] sk)
    {
        super(true, params);

        int v1 = params.getV1();
        int o1 = params.getO1();
        int o2 = params.getO2();

        this.s1 = new short[o1][o2];
        this.t1 = new short[v1][o1];
        this.t4 = new short[v1][o2];
        this.t3 = new short[o1][o2];
        this.l1_F1 = new short[o1][v1][v1];
        this.l1_F2 = new short[o1][v1][o1];
        this.l2_F1 = new short[o2][v1][v1];
        this.l2_F2 = new short[o2][v1][o1];
        this.l2_F3 = new short[o2][v1][o2];
        this.l2_F5 = new short[o2][o1][o1];
        this.l2_F6 = new short[o2][o1][o2];

        int cnt = 0;
        sk_seed = Arrays.copyOfRange(sk, cnt, params.getLen_skseed());
        cnt += sk_seed.length;
        for (int j = 0; j < o2; j++)
        {
            for (int i = 0; i < o1; i++)
            {
                s1[i][j] = (short)(sk[cnt] & GF2Field.MASK);
                cnt++;
            }
        }
        for (int j = 0; j < o1; j++)
        {
            for (int i = 0; i < v1; i++)
            {
                t1[i][j] = (short)(sk[cnt] & GF2Field.MASK);
                cnt++;
            }
        }
        for (int j = 0; j < o2; j++)
        {
            for (int i = 0; i < v1; i++)
            {
                t4[i][j] = (short)(sk[cnt] & GF2Field.MASK);
                cnt++;
            }
        }
        for (int j = 0; j < o2; j++)
        {
            for (int i = 0; i < o1; i++)
            {
                t3[i][j] = (short)(sk[cnt] & GF2Field.MASK);
                cnt++;
            }
        }

        for (int i = 0; i < v1; i++)
        {
            for (int j = 0; j < v1; j++)
            {
                for (int k = 0; k < o1; k++)
                {
                    if (i > j)
                    {
                        this.l1_F1[k][i][j] = 0;
                    }
                    else
                    {
                        this.l1_F1[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                        cnt++;
                    }
                }
            }
        }

        for (int i = 0; i < v1; i++)
        {
            for (int j = 0; j < o1; j++)
            {
                for (int k = 0; k < o1; k++)
                {
                    this.l1_F2[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                    cnt++;
                }
            }
        }

        for (int i = 0; i < v1; i++)
        {
            for (int j = 0; j < v1; j++)
            {
                for (int k = 0; k < o2; k++)
                {
                    if (i > j)
                    {
                        this.l2_F1[k][i][j] = 0;
                    }
                    else
                    {
                        this.l2_F1[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                        cnt++;
                    }
                }
            }
        }

        for (int i = 0; i < v1; i++)
        {
            for (int j = 0; j < o1; j++)
            {
                for (int k = 0; k < o2; k++)
                {
                    this.l2_F2[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                    cnt++;
                }
            }
        }

        for (int i = 0; i < v1; i++)
        {
            for (int j = 0; j < o2; j++)
            {
                for (int k = 0; k < o2; k++)
                {
                    this.l2_F3[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                    cnt++;
                }
            }
        }

        for (int i = 0; i < o1; i++)
        {
            for (int j = 0; j < o1; j++)
            {
                for (int k = 0; k < o2; k++)
                {
                    if (i > j)
                    {
                        this.l2_F5[k][i][j] = 0;
                    }
                    else
                    {
                        this.l2_F5[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                        cnt++;
                    }
                }
            }
        }

        for (int i = 0; i < o1; i++)
        {
            for (int j = 0; j < o2; j++)
            {
                for (int k = 0; k < o2; k++)
                {
                    this.l2_F6[k][i][j] = (short)(sk[cnt] & GF2Field.MASK);
                    cnt++;
                }
            }
        }


    }

    public byte[] getSk_seed()
    {
        return Arrays.clone(sk_seed);
    }

    short[][] getS1()
    {
        return RainbowUtil.cloneArray(s1);
    }

    short[][] getT1()
    {
        return RainbowUtil.cloneArray(t1);
    }

    short[][] getT4()
    {
        return RainbowUtil.cloneArray(t4);
    }

    short[][] getT3()
    {
        return RainbowUtil.cloneArray(t3);
    }

    short[][][] getL1_F1()
    {
        return RainbowUtil.cloneArray(l1_F1);
    }

    short[][][] getL1_F2()
    {
        return RainbowUtil.cloneArray(l1_F2);
    }

    short[][][] getL2_F1()
    {
        return RainbowUtil.cloneArray(l2_F1);
    }

    short[][][] getL2_F2()
    {
        return RainbowUtil.cloneArray(l2_F2);
    }

    short[][][] getL2_F3()
    {
        return RainbowUtil.cloneArray(l2_F3);
    }
    short[][][] getL2_F5()
    {
        return RainbowUtil.cloneArray(l2_F5);
    }

    short[][][] getL2_F6()
    {
        return RainbowUtil.cloneArray(l2_F6);
    }

    public byte[] getEncoded()
    {
        byte[] ret = getSk_seed();
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.s1));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.t1));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.t4));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.t3));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_F1, true));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_F2, false));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F1, true));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F2, false));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F3, false));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F5, true));
        ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_F6, false));
        return ret;
    }
}
