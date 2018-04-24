package org.bouncycastle.crypto.util;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;

/**
 * Basic factory class for message digests.
 */
public final class DigestFactory
{
    public static Digest createMD5()
    {
        return new MD5Digest();
    }

    public static Digest createSHA1()
    {
        return new SHA1Digest();
    }

    public static Digest createSHA224()
    {
        return new SHA224Digest();
    }

    public static Digest createSHA256()
    {
        return new SHA256Digest();
    }

    public static Digest createSHA384()
    {
        return new SHA384Digest();
    }

    public static Digest createSHA512()
    {
        return new SHA512Digest();
    }

    public static Digest createSHA512_224()
    {
        return new SHA512tDigest(224);
    }

    public static Digest createSHA512_256()
    {
        return new SHA512tDigest(256);
    }

    public static Digest createSHA3_224()
    {
        return new SHA3Digest(224);
    }

    public static Digest createSHA3_256()
    {
        return new SHA3Digest(256);
    }

    public static Digest createSHA3_384()
    {
        return new SHA3Digest(384);
    }

    public static Digest createSHA3_512()
    {
        return new SHA3Digest(512);
    }
}
