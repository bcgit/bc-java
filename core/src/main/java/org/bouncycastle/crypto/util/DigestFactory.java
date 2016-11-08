package org.bouncycastle.crypto.util;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;

/**
 * Basic factory class for message digests.
 */
public final class DigestFactory
{
    public static Digest getMD5()
    {
        return new MD5Digest();
    }

    public static Digest getSHA1()
    {
        return new SHA1Digest();
    }

    public static Digest getSHA224()
    {
        return new SHA224Digest();
    }

    public static Digest getSHA256()
    {
        return new SHA256Digest();
    }

    public static Digest getSHA384()
    {
        return new SHA384Digest();
    }

    public static Digest getSHA512()
    {
        return new SHA512Digest();
    }

    public static Digest getSHA512_224()
    {
        return new SHA512tDigest(224);
    }

    public static Digest getSHA512_256()
    {
        return new SHA512tDigest(256);
    }
}
