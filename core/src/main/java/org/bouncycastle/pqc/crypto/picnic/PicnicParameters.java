package org.bouncycastle.pqc.crypto.picnic;

import org.bouncycastle.crypto.CipherParameters;

public class PicnicParameters
    implements CipherParameters
{
    private static class L1Constants
    {
        static final LowmcConstantsL1 INSTANCE = new LowmcConstantsL1();
    }
    private static class L3Constants
    {
        static final LowmcConstantsL3 INSTANCE = new LowmcConstantsL3();
    }
    private static class L5Constants
    {
        static final LowmcConstantsL5 INSTANCE = new LowmcConstantsL5();
    }

    public static final PicnicParameters picnicl1fs = new PicnicParameters("picnicl1fs",  1);
    public static final PicnicParameters picnicl1ur = new PicnicParameters("picnicl1ur",  2);
    public static final PicnicParameters picnicl3fs = new PicnicParameters("picnicl3fs",  3);
    public static final PicnicParameters picnicl3ur = new PicnicParameters("picnicl3ur",  4);
    public static final PicnicParameters picnicl5fs = new PicnicParameters("picnicl5fs",  5);
    public static final PicnicParameters picnicl5ur = new PicnicParameters("picnicl5ur",  6);
    public static final PicnicParameters picnic3l1 = new PicnicParameters("picnic3l1",  7);
    public static final PicnicParameters picnic3l3 = new PicnicParameters("picnic3l3",  8);
    public static final PicnicParameters picnic3l5 = new PicnicParameters("picnic3l5",  9);
    public static final PicnicParameters picnicl1full = new PicnicParameters("picnicl1full",  10);
    public static final PicnicParameters picnicl3full = new PicnicParameters("picnicl3full",  11);
    public static final PicnicParameters picnicl5full = new PicnicParameters("picnicl5full",  12);


    //todo add all parameter sets
    private final String name;
    private final int    param;

    private PicnicParameters(String name, final int param)
    {
        this.name = name;
        this.param = param;
    }

    public String getName()
    {
        return name;
    }

    PicnicEngine getEngine()
    {
        switch (param)
        {
            case 1:
            case 2:
            case 7:
            case 10:
                return new PicnicEngine(param, L1Constants.INSTANCE);
            case 3:
            case 4:
            case 8:
            case 11:
                return new PicnicEngine(param, L3Constants.INSTANCE);
            case 12:
            case 5:
            case 6:
            case 9:
                return new PicnicEngine(param, L5Constants.INSTANCE);
            default:
                return null;
        }
    }
}
