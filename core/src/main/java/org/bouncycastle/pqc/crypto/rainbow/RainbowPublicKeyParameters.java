package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.util.Arrays;

public class RainbowPublicKeyParameters
    extends RainbowKeyParameters
{
    short[][][] pk;

    byte[] pk_seed;
    short[][][] l1_Q3;
    short[][][] l1_Q5;
    short[][][] l1_Q6;
    short[][][] l1_Q9;
    short[][][] l2_Q9;

    RainbowPublicKeyParameters(RainbowParameters params,
                                      short[][][] l1_Q1, short[][][] l1_Q2, short[][][] l1_Q3,
                                      short[][][] l1_Q5, short[][][] l1_Q6, short[][][] l1_Q9,
                                      short[][][] l2_Q1, short[][][] l2_Q2, short[][][] l2_Q3,
                                      short[][][] l2_Q5, short[][][] l2_Q6, short[][][] l2_Q9)
    {
        super(false, params);

        int v1 = params.getV1();
        int o1 = params.getO1();
        int o2 = params.getO2();

        pk = new short[params.getM()][params.getN()][params.getN()];
        for (int k = 0; k < o1; k++)
        {
            for (int i = 0; i < v1; i++)
            {
                System.arraycopy(l1_Q1[k][i], 0, pk[k][i], 0, v1);
                System.arraycopy(l1_Q2[k][i], 0, pk[k][i], v1, o1);
                System.arraycopy(l1_Q3[k][i], 0, pk[k][i], v1 + o1, o2);
            }
            for (int i = 0; i < o1; i++)
            {
                System.arraycopy(l1_Q5[k][i], 0, pk[k][i + v1], v1, o1);
                System.arraycopy(l1_Q6[k][i], 0, pk[k][i + v1], v1 + o1, o2);
            }
            for (int i = 0; i < o2; i++)
            {
                System.arraycopy(l1_Q9[k][i], 0, pk[k][i + v1 + o1], v1 + o1, o2);
            }
        }
        for (int k = 0; k < o2; k++)
        {
            for (int i = 0; i < v1; i++)
            {
                System.arraycopy(l2_Q1[k][i], 0, pk[k + o1][i], 0, v1);
                System.arraycopy(l2_Q2[k][i], 0, pk[k + o1][i], v1, o1);
                System.arraycopy(l2_Q3[k][i], 0, pk[k + o1][i], v1 + o1, o2);
            }
            for (int i = 0; i < o1; i++)
            {
                System.arraycopy(l2_Q5[k][i], 0, pk[k + o1][i + v1], v1, o1);
                System.arraycopy(l2_Q6[k][i], 0, pk[k + o1][i + v1], v1 + o1, o2);
            }
            for (int i = 0; i < o2; i++)
            {
                System.arraycopy(l2_Q9[k][i], 0, pk[k + o1][i + v1 + o1], v1 + o1, o2);
            }
        }
    }

    RainbowPublicKeyParameters(RainbowParameters params,
                                            byte[] pk_seed,
                                            short[][][] l1_Q3, short[][][] l1_Q5,
                                            short[][][] l1_Q6, short[][][] l1_Q9,
                                            short[][][] l2_Q9)
    {
        super(false, params);

        this.pk_seed = pk_seed.clone();
        this.l1_Q3 = RainbowUtil.cloneArray(l1_Q3);
        this.l1_Q5 = RainbowUtil.cloneArray(l1_Q5);
        this.l1_Q6 = RainbowUtil.cloneArray(l1_Q6);
        this.l1_Q9 = RainbowUtil.cloneArray(l1_Q9);
        this.l2_Q9 = RainbowUtil.cloneArray(l2_Q9);
    }

    public RainbowPublicKeyParameters(RainbowParameters params, byte[] encoding)
    {
        super(false, params);

        int m = params.getM();
        int n = params.getN();

        if (getParameters().getVersion() == Version.CLASSIC)
        {
            this.pk = new short[m][n][n];
            int cnt = 0;
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    for (int k = 0; k < m; k++)
                    {
                        if (i > j)
                        {
                            this.pk[k][i][j] = 0;
                        }
                        else
                        {
                            this.pk[k][i][j] = (short)(encoding[cnt] & GF2Field.MASK);
                            cnt++;
                        }
                    }
                }
            }
        }
        else
        {
            this.pk_seed = Arrays.copyOfRange(encoding, 0, params.getLen_pkseed());

            this.l1_Q3 = new short[params.getO1()][params.getV1()][params.getO2()];
            this.l1_Q5 = new short[params.getO1()][params.getO1()][params.getO1()];
            this.l1_Q6 = new short[params.getO1()][params.getO1()][params.getO2()];
            this.l1_Q9 = new short[params.getO1()][params.getO2()][params.getO2()];
            this.l2_Q9 = new short[params.getO2()][params.getO2()][params.getO2()];

            int offSet = params.getLen_pkseed();
            offSet += RainbowUtil.loadEncoded(this.l1_Q3, encoding, offSet, false);
            offSet += RainbowUtil.loadEncoded(this.l1_Q5, encoding, offSet, true);
            offSet += RainbowUtil.loadEncoded(this.l1_Q6, encoding, offSet, false);
            offSet += RainbowUtil.loadEncoded(this.l1_Q9, encoding, offSet, true);
            offSet += RainbowUtil.loadEncoded(this.l2_Q9, encoding, offSet, true);

            if (offSet != encoding.length)
            {
                throw new IllegalArgumentException("unparsed data in key encoding");
            }
        }
    }

    public short[][][] getPk()
    {
        return RainbowUtil.cloneArray(pk);
    }

    public byte[] getEncoded()
    {
        if (getParameters().getVersion() != Version.CLASSIC)
        {
            byte[] ret = pk_seed;
            ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_Q3, false));
            ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_Q5, true));
            ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_Q6, false));
            ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l1_Q9, true));
            ret = Arrays.concatenate(ret, RainbowUtil.getEncoded(this.l2_Q9, true));
            return ret;
        }

        return RainbowUtil.getEncoded(pk, true);
    }
}
