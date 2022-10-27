package org.bouncycastle.pqc.crypto.rainbow;

public class RainbowPublicKeyParameters
    extends RainbowKeyParameters
{
    short[][][] pk;

    public RainbowPublicKeyParameters(RainbowParameters params,
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

    public RainbowPublicKeyParameters(RainbowParameters params, byte[] pk)
    {
        super(false, params);

        int m = params.getM();
        int n = params.getN();

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
                        this.pk[k][i][j] = (short)(pk[cnt] & GF2Field.MASK);
                        cnt++;
                    }
                }
            }
        }
    }

    public short[][][] getPk()
    {
        return RainbowUtil.cloneArray(pk);
    }

    public byte[] getEncoded()
    {
        return RainbowUtil.getEncoded(pk, true);
    }
}
