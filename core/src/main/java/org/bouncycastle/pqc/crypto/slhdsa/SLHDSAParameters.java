package org.bouncycastle.pqc.crypto.slhdsa;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

public class SLHDSAParameters
{
    // "Pure" SLH-DSA Parameters
    // SHA-2
    public static final SLHDSAParameters sha2_128f = new SLHDSAParameters(
        Integers.valueOf(0x010201), "sha2-128f", new Sha2EngineProvider(16, 16, 22, 6, 33, 66), null);
    public static final SLHDSAParameters sha2_128s = new SLHDSAParameters(
        Integers.valueOf(0x010202), "sha2-128s", new Sha2EngineProvider(16, 16, 7, 12, 14, 63), null);

    public static final SLHDSAParameters sha2_192f = new SLHDSAParameters(
        Integers.valueOf(0x010203), "sha2-192f", new Sha2EngineProvider(24, 16, 22, 8, 33, 66), null);
    public static final SLHDSAParameters sha2_192s = new SLHDSAParameters(
        Integers.valueOf(0x010204), "sha2-192s", new Sha2EngineProvider(24, 16, 7, 14, 17, 63), null);

    public static final SLHDSAParameters sha2_256f = new SLHDSAParameters(
        Integers.valueOf(0x010205), "sha2-256f", new Sha2EngineProvider(32, 16, 17, 9, 35, 68), null);
    public static final SLHDSAParameters sha2_256s = new SLHDSAParameters(
        Integers.valueOf(0x010206), "sha2-256s", new Sha2EngineProvider(32, 16, 8, 14, 22, 64), null);

    // SHAKE-256.
    public static final SLHDSAParameters shake_128f = new SLHDSAParameters(
        Integers.valueOf(0x020201), "shake-128f", new Shake256EngineProvider(16, 16, 22, 6, 33, 66), null);
    public static final SLHDSAParameters shake_128s = new SLHDSAParameters(
        Integers.valueOf(0x020202), "shake-128s", new Shake256EngineProvider(16, 16, 7, 12, 14, 63), null);

    public static final SLHDSAParameters shake_192f = new SLHDSAParameters(
        Integers.valueOf(0x020203), "shake-192f", new Shake256EngineProvider(24, 16, 22, 8, 33, 66), null);
    public static final SLHDSAParameters shake_192s = new SLHDSAParameters(
        Integers.valueOf(0x020204), "shake-192s", new Shake256EngineProvider(24, 16, 7, 14, 17, 63), null);

    public static final SLHDSAParameters shake_256f = new SLHDSAParameters(
        Integers.valueOf(0x020205), "shake-256f", new Shake256EngineProvider(32, 16, 17, 9, 35, 68), null);
    public static final SLHDSAParameters shake_256s = new SLHDSAParameters(
        Integers.valueOf(0x020206), "shake-256s", new Shake256EngineProvider(32, 16, 8, 14, 22, 64), null);


    // "Pre-hash" SLH-DSA Parameters
    // SHA-2
    public static final SLHDSAParameters sha2_128f_with_sha256 = new SLHDSAParameters(
            Integers.valueOf(0x010201), "sha2-128f-with-sha256", new Sha2EngineProvider(16, 16, 22, 6, 33, 66), new SHA256Digest());
    public static final SLHDSAParameters sha2_128s_with_sha256 = new SLHDSAParameters(
            Integers.valueOf(0x010202), "sha2-128s-with-sha256", new Sha2EngineProvider(16, 16, 7, 12, 14, 63), new SHA256Digest());

    public static final SLHDSAParameters sha2_192f_with_sha512 = new SLHDSAParameters(
            Integers.valueOf(0x010203), "sha2-192f-with-sha512", new Sha2EngineProvider(24, 16, 22, 8, 33, 66), new SHA512Digest());
    public static final SLHDSAParameters sha2_192s_with_sha512 = new SLHDSAParameters(
            Integers.valueOf(0x010204), "sha2-192s-with-sha512", new Sha2EngineProvider(24, 16, 7, 14, 17, 63), new SHA512Digest());

    public static final SLHDSAParameters sha2_256f_with_sha512 = new SLHDSAParameters(
            Integers.valueOf(0x010205), "sha2-256f-with-sha512", new Sha2EngineProvider(32, 16, 17, 9, 35, 68), new SHA512Digest());
    public static final SLHDSAParameters sha2_256s_with_sha512 = new SLHDSAParameters(
            Integers.valueOf(0x010206), "sha2-256s-with-sha512", new Sha2EngineProvider(32, 16, 8, 14, 22, 64), new SHA512Digest());

    // SHAKE-256.
    public static final SLHDSAParameters shake_128f_with_shake128 = new SLHDSAParameters(
            Integers.valueOf(0x020201), "shake-128f-with-shake128", new Shake256EngineProvider(16, 16, 22, 6, 33, 66), new SHAKEDigest(128));
    public static final SLHDSAParameters shake_128s_with_shake128 = new SLHDSAParameters(
            Integers.valueOf(0x020202), "shake-128s-with-shake128", new Shake256EngineProvider(16, 16, 7, 12, 14, 63), new SHAKEDigest(128));

    public static final SLHDSAParameters shake_192f_with_shake256 = new SLHDSAParameters(
            Integers.valueOf(0x020203), "shake-192f-with-shake256", new Shake256EngineProvider(24, 16, 22, 8, 33, 66), new SHAKEDigest(256));
    public static final SLHDSAParameters shake_192s_with_shake256 = new SLHDSAParameters(
            Integers.valueOf(0x020204), "shake-192s-with-shake256", new Shake256EngineProvider(24, 16, 7, 14, 17, 63), new SHAKEDigest(256));

    public static final SLHDSAParameters shake_256f_with_shake256 = new SLHDSAParameters(
            Integers.valueOf(0x020205), "shake-256f-with-shake256", new Shake256EngineProvider(32, 16, 17, 9, 35, 68), new SHAKEDigest(256));
    public static final SLHDSAParameters shake_256s_with_shake256 = new SLHDSAParameters(
            Integers.valueOf(0x020206), "shake-256s-with-shake256", new Shake256EngineProvider(32, 16, 8, 14, 22, 64), new SHAKEDigest(256));


    private static final Map<Integer, SLHDSAParameters> ID_TO_PARAMS = new HashMap<Integer, SLHDSAParameters>();

    static
    {
        SLHDSAParameters[] all = new SLHDSAParameters[]{
            SLHDSAParameters.sha2_128f, SLHDSAParameters.sha2_128s,
            SLHDSAParameters.sha2_192f, SLHDSAParameters.sha2_192s,
            SLHDSAParameters.sha2_256f, SLHDSAParameters.sha2_256s,
            SLHDSAParameters.shake_128f, SLHDSAParameters.shake_128s,
            SLHDSAParameters.shake_192f, SLHDSAParameters.shake_192s,
            SLHDSAParameters.shake_256f, SLHDSAParameters.shake_256s,

            SLHDSAParameters.sha2_128f_with_sha256, SLHDSAParameters.sha2_128s_with_sha256,
            SLHDSAParameters.sha2_192f_with_sha512, SLHDSAParameters.sha2_192s_with_sha512,
            SLHDSAParameters.sha2_256f_with_sha512, SLHDSAParameters.sha2_256s_with_sha512,
            SLHDSAParameters.shake_128f_with_shake128, SLHDSAParameters.shake_128s_with_shake128,
            SLHDSAParameters.shake_192f_with_shake256, SLHDSAParameters.shake_192s_with_shake256,
            SLHDSAParameters.shake_256f_with_shake256, SLHDSAParameters.shake_256s_with_shake256,
        };

        for (int i = 0; i < all.length; ++i)
        {
            SLHDSAParameters parameters = all[i];
            ID_TO_PARAMS.put(parameters.getID(), parameters);
        }
    }

    private final Integer id;
    private final String name;
    private final SLHDSAEngineProvider engineProvider;
    private final Digest preHashDigest;

    private SLHDSAParameters(Integer id, String name, SLHDSAEngineProvider engineProvider, Digest preHashDigest)
    {
        this.id = id;
        this.name = name;
        this.engineProvider = engineProvider;
        this.preHashDigest = preHashDigest;
    }

    public Integer getID()
    {
        return id;
    }

    public String getName()
    {
        return name;
    }

    int getN()
    {
        return engineProvider.getN();
    }

    SLHDSAEngine getEngine()
    {
        return engineProvider.get();
    }

    public Digest getDigest()
    {
        return preHashDigest;
    }

    /**
     * Return the SLH-DSA parameters that map to the passed in parameter ID.
     *
     * @param id the oid of interest.
     * @return the parameter set.
     */
    public static SLHDSAParameters getParams(Integer id)
    {
        return (SLHDSAParameters)ID_TO_PARAMS.get(id);
    }

    public byte[] getEncoded()
    {
        return Pack.intToBigEndian(getID().intValue());
    }

    private static class Sha2EngineProvider
        implements SLHDSAEngineProvider
    {
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Sha2EngineProvider(int n, int w, int d, int a, int k, int h)
        {
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN()
        {
            return n;
        }

        public SLHDSAEngine get()
        {
            return new SLHDSAEngine.Sha2Engine(n, w, d, a, k, h);
        }
    }

    private static class Shake256EngineProvider
        implements SLHDSAEngineProvider
    {
        private final int n;
        private final int w;
        private final int d;
        private final int a;
        private final int k;
        private final int h;

        public Shake256EngineProvider(int n, int w, int d, int a, int k, int h)
        {
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int getN()
        {
            return n;
        }

        public SLHDSAEngine get()
        {
            return new SLHDSAEngine.Shake256Engine(n, w, d, a, k, h);
        }
    }
}
