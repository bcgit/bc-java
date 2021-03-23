package org.bouncycastle.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Basic factory class for message digests.
 */
public final class DigestFactory
{
    private static final Map cloneMap = new HashMap();

    private static interface Cloner
    {
        Digest createClone(Digest original);
    }

    static
    {
         cloneMap.put(createMD5().getAlgorithmName(), new Cloner() {
             public Digest createClone(Digest original)
             {
                 return new MD5Digest((MD5Digest)original);
             }
         });
        cloneMap.put(createSHA1().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new MD5Digest((MD5Digest)original);
            }
        });
        cloneMap.put(createSHA224().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA224Digest((SHA224Digest)original);
            }
        });
        cloneMap.put(createSHA256().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA256Digest((SHA256Digest)original);
            }
        });
        cloneMap.put(createSHA384().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA384Digest((SHA384Digest)original);
            }
        });
        cloneMap.put(createSHA512().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA512Digest((SHA512Digest)original);
            }
        });
        cloneMap.put(createSHA3_224().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA3Digest((SHA3Digest)original);
            }
        });
        cloneMap.put(createSHA3_256().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA3Digest((SHA3Digest)original);
            }
        });
        cloneMap.put(createSHA3_384().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA3Digest((SHA3Digest)original);
            }
        });
        cloneMap.put(createSHA3_512().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHA3Digest((SHA3Digest)original);
            }
        });

        cloneMap.put(createSHAKE128().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHAKEDigest((SHAKEDigest)original);
            }
        });

        cloneMap.put(createSHAKE256().getAlgorithmName(), new Cloner() {
            public Digest createClone(Digest original)
            {
                return new SHAKEDigest((SHAKEDigest)original);
            }
        });
    }

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

    public static Digest createSHAKE128()
    {
        return new SHAKEDigest(128);
    }

    public static Digest createSHAKE256()
    {
        return new SHAKEDigest(256);
    }

    public static Digest cloneDigest(Digest hashAlg)
    {
        return ((Cloner)cloneMap.get(hashAlg.getAlgorithmName())).createClone(hashAlg);
    }
}
