package org.bouncycastle.jcajce.provider.util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.util.Strings;

public class DigestFactory
{
    private static Set md5 = new HashSet();
    private static Set sha1 = new HashSet();
    private static Set sha224 = new HashSet();
    private static Set sha256 = new HashSet();
    private static Set sha384 = new HashSet();
    private static Set sha512 = new HashSet();
    private static Set sha512_224 = new HashSet();
    private static Set sha512_256 = new HashSet();
    private static Set sha3_224 = new HashSet();
    private static Set sha3_256 = new HashSet();
    private static Set sha3_384 = new HashSet();
    private static Set sha3_512 = new HashSet();
    private static Set ripemd128 = new HashSet();
    private static Set ripemd160 = new HashSet();
    private static Set ripemd256 = new HashSet();
    private static Set shake128 = new HashSet();
    private static Set shake256 = new HashSet();

    private static Map oids = new HashMap();
    
    static
    {
        md5.add("MD5");
        md5.add(PKCSObjectIdentifiers.md5.getId());
        
        sha1.add("SHA1");
        sha1.add("SHA-1");
        sha1.add(OIWObjectIdentifiers.idSHA1.getId());
        
        sha224.add("SHA224");
        sha224.add("SHA-224");
        sha224.add(NISTObjectIdentifiers.id_sha224.getId());
        
        sha256.add("SHA256");
        sha256.add("SHA-256");
        sha256.add(NISTObjectIdentifiers.id_sha256.getId());
        
        sha384.add("SHA384");
        sha384.add("SHA-384");
        sha384.add(NISTObjectIdentifiers.id_sha384.getId());
        
        sha512.add("SHA512");
        sha512.add("SHA-512");
        sha512.add(NISTObjectIdentifiers.id_sha512.getId()); 

        sha512_224.add("SHA512(224)");
        sha512_224.add("SHA-512(224)");
        sha512_224.add(NISTObjectIdentifiers.id_sha512_224.getId());

        sha512_256.add("SHA512(256)");
        sha512_256.add("SHA-512(256)");
        sha512_256.add(NISTObjectIdentifiers.id_sha512_256.getId());

        sha3_224.add("SHA3-224");
        sha3_224.add(NISTObjectIdentifiers.id_sha3_224.getId());

        sha3_256.add("SHA3-256");
        sha3_256.add(NISTObjectIdentifiers.id_sha3_256.getId());

        sha3_384.add("SHA3-384");
        sha3_384.add(NISTObjectIdentifiers.id_sha3_384.getId());

        sha3_512.add("SHA3-512");
        sha3_512.add(NISTObjectIdentifiers.id_sha3_512.getId());

        shake128.add("SHAKE128");
        shake128.add(NISTObjectIdentifiers.id_shake128.getId());

        shake256.add("SHAKE256");
        shake256.add(NISTObjectIdentifiers.id_shake256.getId());

        ripemd128.add("RIPEMD128");
        ripemd128.add("RIPEMD-128");
        ripemd128.add(TeleTrusTObjectIdentifiers.ripemd128.getId());

        ripemd160.add("RIPEMD160");
        ripemd160.add("RIPEMD-160");
        ripemd160.add(TeleTrusTObjectIdentifiers.ripemd160.getId());

        ripemd256.add("RIPEMD256");
        ripemd256.add("RIPEMD-256");
        ripemd256.add(TeleTrusTObjectIdentifiers.ripemd256.getId());

        oids.put("MD5", PKCSObjectIdentifiers.md5);
        oids.put(PKCSObjectIdentifiers.md5.getId(), PKCSObjectIdentifiers.md5);

        oids.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
        oids.put("RIPEMD-128", TeleTrusTObjectIdentifiers.ripemd128);
        oids.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), TeleTrusTObjectIdentifiers.ripemd128);

        oids.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
        oids.put("RIPEMD-160", TeleTrusTObjectIdentifiers.ripemd160);
        oids.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), TeleTrusTObjectIdentifiers.ripemd160);

        oids.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);
        oids.put("RIPEMD-256", TeleTrusTObjectIdentifiers.ripemd256);
        oids.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), TeleTrusTObjectIdentifiers.ripemd256);
        
        oids.put("SHA1", OIWObjectIdentifiers.idSHA1);
        oids.put("SHA-1", OIWObjectIdentifiers.idSHA1);
        oids.put(OIWObjectIdentifiers.idSHA1.getId(), OIWObjectIdentifiers.idSHA1);
        
        oids.put("SHA224", NISTObjectIdentifiers.id_sha224);
        oids.put("SHA-224", NISTObjectIdentifiers.id_sha224);
        oids.put(NISTObjectIdentifiers.id_sha224.getId(), NISTObjectIdentifiers.id_sha224);
        
        oids.put("SHA256", NISTObjectIdentifiers.id_sha256);
        oids.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        oids.put(NISTObjectIdentifiers.id_sha256.getId(), NISTObjectIdentifiers.id_sha256);
        
        oids.put("SHA384", NISTObjectIdentifiers.id_sha384);
        oids.put("SHA-384", NISTObjectIdentifiers.id_sha384);
        oids.put(NISTObjectIdentifiers.id_sha384.getId(), NISTObjectIdentifiers.id_sha384);
        
        oids.put("SHA512", NISTObjectIdentifiers.id_sha512);
        oids.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        oids.put(NISTObjectIdentifiers.id_sha512.getId(), NISTObjectIdentifiers.id_sha512);

        oids.put("SHA512(224)", NISTObjectIdentifiers.id_sha512_224);
        oids.put("SHA-512(224)", NISTObjectIdentifiers.id_sha512_224);
        oids.put(NISTObjectIdentifiers.id_sha512_224.getId(), NISTObjectIdentifiers.id_sha512_224);

        oids.put("SHA512(256)", NISTObjectIdentifiers.id_sha512_256);
        oids.put("SHA-512(256)", NISTObjectIdentifiers.id_sha512_256);
        oids.put(NISTObjectIdentifiers.id_sha512_256.getId(), NISTObjectIdentifiers.id_sha512_256);

        oids.put("SHA3-224", NISTObjectIdentifiers.id_sha3_224);
        oids.put(NISTObjectIdentifiers.id_sha3_224.getId(), NISTObjectIdentifiers.id_sha3_224);

        oids.put("SHA3-256", NISTObjectIdentifiers.id_sha3_256);
        oids.put(NISTObjectIdentifiers.id_sha3_256.getId(), NISTObjectIdentifiers.id_sha3_256);

        oids.put("SHA3-384", NISTObjectIdentifiers.id_sha3_384);
        oids.put(NISTObjectIdentifiers.id_sha3_384.getId(), NISTObjectIdentifiers.id_sha3_384);

        oids.put("SHA3-512", NISTObjectIdentifiers.id_sha3_512);
        oids.put(NISTObjectIdentifiers.id_sha3_512.getId(), NISTObjectIdentifiers.id_sha3_512);

        oids.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        oids.put(NISTObjectIdentifiers.id_shake128.getId(), NISTObjectIdentifiers.id_shake128);

        oids.put("SHAKE256", NISTObjectIdentifiers.id_shake256);
        oids.put(NISTObjectIdentifiers.id_shake256.getId(), NISTObjectIdentifiers.id_shake256);
    }
    
    public static Digest getDigest(
        String digestName) 
    {
        digestName = Strings.toUpperCase(digestName);
        
        if (sha1.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA1();
        }
        if (md5.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createMD5();
        }
        if (sha224.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA224();
        }
        if (sha256.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA256();
        }
        if (sha384.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA384();
        }
        if (sha512.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA512();
        }
        if (sha512_224.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA512_224();
        }
        if (sha512_256.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA512_256();
        }

        if (sha3_224.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA3_224();
        }
        if (sha3_256.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA3_256();
        }
        if (sha3_384.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA3_384();
        }
        if (sha3_512.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHA3_512();
        }
        if (ripemd128.contains(digestName))
        {
            return new RIPEMD128Digest();
        }
        if (ripemd160.contains(digestName))
        {
            return new RIPEMD160Digest();
        }
        if (ripemd256.contains(digestName))
        {
            return new RIPEMD256Digest();
        }
        if (shake128.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHAKE128();
        }
        if (shake256.contains(digestName))
        {
            return org.bouncycastle.crypto.util.DigestFactory.createSHAKE256();
        }

        return null;
    }
    
    public static boolean isSameDigest(
        String digest1,
        String digest2)
    {
        // the alias sets below cover only the SHA families and MD5, so without this two identical
        // names for anything else - RIPEMD160, Whirlpool, SM3, GOST3411 - were reported as
        // different digests, and PSS refused a PSSParameterSpec naming the same digest twice
        // (github #2381)
        if (digest1 != null && digest1.equalsIgnoreCase(digest2))
        {
            return true;
        }

        return (sha1.contains(digest1) && sha1.contains(digest2))
            || (sha224.contains(digest1) && sha224.contains(digest2))
            || (sha256.contains(digest1) && sha256.contains(digest2))
            || (sha384.contains(digest1) && sha384.contains(digest2))
            || (sha512.contains(digest1) && sha512.contains(digest2))
            || (sha512_224.contains(digest1) && sha512_224.contains(digest2))
            || (sha512_256.contains(digest1) && sha512_256.contains(digest2))
            || (sha3_224.contains(digest1) && sha3_224.contains(digest2))
            || (sha3_256.contains(digest1) && sha3_256.contains(digest2))
            || (sha3_384.contains(digest1) && sha3_384.contains(digest2))
            || (sha3_512.contains(digest1) && sha3_512.contains(digest2))
            || (md5.contains(digest1) && md5.contains(digest2))
            || (ripemd128.contains(digest1) && ripemd128.contains(digest2))
            || (ripemd160.contains(digest1) && ripemd160.contains(digest2))
            || (ripemd256.contains(digest1) && ripemd256.contains(digest2));
    }
    
    public static ASN1ObjectIdentifier getOID(
        String digestName)
    {
        return (ASN1ObjectIdentifier)oids.get(digestName);
    }
}
