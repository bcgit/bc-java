package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.KEMParameters;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048509;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048677;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS40961229;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS4096821;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSS1373;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSS701;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;

/**
 * NTRU cipher parameter sets
 */
public class NTRUParameters
    implements KEMParameters
{
    /**
     * NTRU-HPS parameter set with n = 509 and q = 2048.
     */
    public static final NTRUParameters ntruhps2048509 = new NTRUParameters("ntruhps2048509", new NTRUHPS2048509());
    /**
     * NTRU-HPS parameter set with n = 677 and q = 2048.
     */
    public static final NTRUParameters ntruhps2048677 = new NTRUParameters("ntruhps2048677", new NTRUHPS2048677());
    /**
     * NTRU-HPS parameter set with n = 821 and q = 4096.
     */
    public static final NTRUParameters ntruhps4096821 = new NTRUParameters("ntruhps4096821", new NTRUHPS4096821());

    /**
     * NTRU-HPS parameter set with n = 1229 and q = 4096.
     */
    public static final NTRUParameters ntruhps40961229 = new NTRUParameters("ntruhps40961229", new NTRUHPS40961229());

    /**
     * NTRU-HRSS parameter set with n = 701.
     */
    public static final NTRUParameters ntruhrss701 = new NTRUParameters("ntruhrss701", new NTRUHRSS701());

    /**
     * NTRU-HRSS parameter set with n = 1373.
     */
    public static final NTRUParameters ntruhrss1373 = new NTRUParameters("ntruhrss1373", new NTRUHRSS1373());

    private final String name;
    /**
     * Currently selected parameter set
     */
    final NTRUParameterSet parameterSet;

    private NTRUParameters(String name, NTRUParameterSet parameterSet)
    {
        this.name = name;
        this.parameterSet = parameterSet;
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return parameterSet.sharedKeyBytes() * 8;
    }
}
