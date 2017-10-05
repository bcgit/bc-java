package org.bouncycastle.crypto.signers;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

public class ISOTrailers
{
    private static final Map<String, Integer> trailerMap;

    static final public int   TRAILER_IMPLICIT    = 0xBC;

    static final public int   TRAILER_RIPEMD160   = 0x31CC;
    static final public int   TRAILER_RIPEMD128   = 0x32CC;
    static final public int   TRAILER_SHA1        = 0x33CC;
    static final public int   TRAILER_SHA256      = 0x34CC;
    static final public int   TRAILER_SHA512      = 0x35CC;
    static final public int   TRAILER_SHA384      = 0x36CC;
    static final public int   TRAILER_WHIRLPOOL   = 0x37CC;
    static final public int   TRAILER_SHA224      = 0x38CC;
    static final public int   TRAILER_SHA512_224  = 0x39CC;
    static final public int   TRAILER_SHA512_256  = 0x3aCC;

    static
    {
        Map<String, Integer> trailers = new HashMap<String, Integer>();

        trailers.put("RIPEMD128", Integers.valueOf(TRAILER_RIPEMD128));
        trailers.put("RIPEMD160", Integers.valueOf(TRAILER_RIPEMD160));

        trailers.put("SHA-1", Integers.valueOf(TRAILER_SHA1));
        trailers.put("SHA-224", Integers.valueOf(TRAILER_SHA224));
        trailers.put("SHA-256", Integers.valueOf(TRAILER_SHA256));
        trailers.put("SHA-384", Integers.valueOf(TRAILER_SHA384));
        trailers.put("SHA-512", Integers.valueOf(TRAILER_SHA512));
        trailers.put("SHA-512/224", Integers.valueOf(TRAILER_SHA512_224));
        trailers.put("SHA-512/256", Integers.valueOf(TRAILER_SHA512_256));

        trailers.put("Whirlpool", Integers.valueOf(TRAILER_WHIRLPOOL));

        trailerMap = Collections.unmodifiableMap(trailers);
    }

    public static Integer getTrailer(Digest digest)
    {
        return (Integer)trailerMap.get(digest.getAlgorithmName());  // JDK 1.4 compatibility
    }

    public static boolean noTrailerAvailable(Digest digest)
    {
        return !trailerMap.containsKey(digest.getAlgorithmName());
    }
}
