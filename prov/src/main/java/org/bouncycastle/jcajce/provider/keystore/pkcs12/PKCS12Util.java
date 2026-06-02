package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.internal.asn1.nsri.NSRIObjectIdentifiers;
import org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * Internal helper used by the PKCS#12 keystore SPIs in this package.
 * Mirrors the validation and content-extraction helpers from the deprecated
 * {@link org.bouncycastle.jce.PKCS12Util}, without the JCE
 * {@code convertToDefiniteLength} re-encoding API.
 */
class PKCS12Util
{
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    /**
     * Key sizes (in bits) for the symmetric cipher OIDs that PKCS#12
     * parameter-derivation paths need to know about. Used by both
     * {@link PKCS12KeyStoreSpi} and {@link PKCS12PBMAC1KeyStoreSpi} to
     * size derived keys for legacy PBE and PBES2 schemes.
     */
    private static final Map<ASN1ObjectIdentifier, Integer> KEY_SIZES;

    static
    {
        Map<ASN1ObjectIdentifier, Integer> sizes = new HashMap<ASN1ObjectIdentifier, Integer>();

        sizes.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));

        sizes.put(PKCSObjectIdentifiers.des_EDE3_CBC, Integers.valueOf(192));

        sizes.put(NISTObjectIdentifiers.id_aes128_CBC, Integers.valueOf(128));
        sizes.put(NISTObjectIdentifiers.id_aes192_CBC, Integers.valueOf(192));
        sizes.put(NISTObjectIdentifiers.id_aes256_CBC, Integers.valueOf(256));

        sizes.put(NISTObjectIdentifiers.id_aes128_GCM, Integers.valueOf(128));
        sizes.put(NISTObjectIdentifiers.id_aes192_GCM, Integers.valueOf(192));
        sizes.put(NISTObjectIdentifiers.id_aes256_GCM, Integers.valueOf(256));

        sizes.put(NTTObjectIdentifiers.id_camellia128_cbc, Integers.valueOf(128));
        sizes.put(NTTObjectIdentifiers.id_camellia192_cbc, Integers.valueOf(192));
        sizes.put(NTTObjectIdentifiers.id_camellia256_cbc, Integers.valueOf(256));

        sizes.put(CryptoProObjectIdentifiers.gostR28147_gcfb, Integers.valueOf(256));

        KEY_SIZES = Collections.unmodifiableMap(sizes);
    }

    /**
     * Return the key size, in bits, for the symmetric cipher named by
     * {@code algorithmIdentifier}, or {@code -1} if BC's PKCS#12 layer
     * doesn't recognise the OID. Not every cipher / OID relationship is
     * captured here — this is a pragmatic table for the OIDs the keystore
     * SPIs actually have to size keys for.
     */
    static int getKeySize(AlgorithmIdentifier algorithmIdentifier)
    {
        Integer keySize = (Integer)KEY_SIZES.get(algorithmIdentifier.getAlgorithm());
        return keySize == null ? -1 : keySize.intValue();
    }

    /**
     * Resolve a SecretKey to its standards-published bag OID (RFC 7292 sec.
     * 4.2.5 secretBag), or {@code null} if the algorithm has no recognised
     * OID in this implementation. Coverage:
     * <ul>
     * <li>AES (by key length, RFC 3565 OIDs)</li>
     * <li>DESede / TripleDES / 3DES (PKCS#5)</li>
     * <li>SEED (RFC 4269, KISA arc)</li>
     * <li>ARIA (by key length, RFC 5794 / NSRI arc)</li>
     * <li>Camellia (by key length, RFC 3657 / NTT arc)</li>
     * <li>HMAC-SHA1 / SHA-2 / SHA-3 families</li>
     * </ul>
     * Other algorithms are rejected at setEntry-time (github #1807).
     */
    static ASN1ObjectIdentifier resolveSecretKeyOid(SecretKey key)
    {
        String alg = key.getAlgorithm();
        if (alg == null)
        {
            return null;
        }

        // If the algorithm name itself parses as an ASN.1 OID, accept it
        // as the secretTypeId verbatim. Round-tripping works because
        // resolveSecretKeyAlgName falls back to the OID's string form
        // for unrecognised OIDs (the JCE SecretKeySpec accepts any
        // non-empty string as the algorithm name).
        ASN1ObjectIdentifier asOid = ASN1ObjectIdentifier.tryFromID(alg);
        if (asOid != null)
        {
            return asOid;
        }

        String upper = Strings.toUpperCase(alg);
        if ("AES".equals(upper))
        {
            byte[] enc = key.getEncoded();
            if (enc == null)
            {
                return null;
            }
            switch (enc.length)
            {
            case 16: return NISTObjectIdentifiers.id_aes128_CBC;
            case 24: return NISTObjectIdentifiers.id_aes192_CBC;
            case 32: return NISTObjectIdentifiers.id_aes256_CBC;
            default: return null;
            }
        }
        if ("DESEDE".equals(upper) || "TRIPLEDES".equals(upper) || "3DES".equals(upper))
        {
            return PKCSObjectIdentifiers.des_EDE3_CBC;
        }
        if ("SEED".equals(upper))
        {
            return KISAObjectIdentifiers.id_seedCBC;
        }
        if ("ARIA".equals(upper))
        {
            byte[] enc = key.getEncoded();
            if (enc == null)
            {
                return null;
            }
            switch (enc.length)
            {
            case 16: return NSRIObjectIdentifiers.id_aria128_cbc;
            case 24: return NSRIObjectIdentifiers.id_aria192_cbc;
            case 32: return NSRIObjectIdentifiers.id_aria256_cbc;
            default: return null;
            }
        }
        if ("CAMELLIA".equals(upper))
        {
            byte[] enc = key.getEncoded();
            if (enc == null)
            {
                return null;
            }
            switch (enc.length)
            {
            case 16: return NTTObjectIdentifiers.id_camellia128_cbc;
            case 24: return NTTObjectIdentifiers.id_camellia192_cbc;
            case 32: return NTTObjectIdentifiers.id_camellia256_cbc;
            default: return null;
            }
        }
        if ("HMACSHA1".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA1;
        }
        if ("HMACSHA224".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA224;
        }
        if ("HMACSHA256".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA256;
        }
        if ("HMACSHA384".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA384;
        }
        if ("HMACSHA512".equals(upper))
        {
            return PKCSObjectIdentifiers.id_hmacWithSHA512;
        }
        if ("HMACSHA3-224".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_224;
        }
        if ("HMACSHA3-256".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_256;
        }
        if ("HMACSHA3-384".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_384;
        }
        if ("HMACSHA3-512".equals(upper))
        {
            return NISTObjectIdentifiers.id_hmacWithSHA3_512;
        }
        return null;
    }

    /**
     * Reverse of {@link #resolveSecretKeyOid(SecretKey)}: given a
     * secretTypeId from a SafeBag of type secretBag, return the JCA
     * algorithm name to feed into {@code SecretKeySpec}. For secretTypeIds
     * that BC has a canonical name for, returns the canonical name (e.g.
     * {@code "AES"}, {@code "HmacSHA256"}); for any other valid OID, falls
     * back to the OID's string form so the SecretKey can still be
     * retrieved through {@code KeyStore.getKey(...)} — JCE's
     * {@code SecretKeySpec} accepts any non-empty algorithm string.
     */
    static String resolveSecretKeyAlgName(ASN1ObjectIdentifier oid)
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(oid)
            || NISTObjectIdentifiers.id_aes192_CBC.equals(oid)
            || NISTObjectIdentifiers.id_aes256_CBC.equals(oid))
        {
            return "AES";
        }
        if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(oid))
        {
            return "DESede";
        }
        if (KISAObjectIdentifiers.id_seedCBC.equals(oid))
        {
            return "SEED";
        }
        if (NSRIObjectIdentifiers.id_aria128_cbc.equals(oid)
            || NSRIObjectIdentifiers.id_aria192_cbc.equals(oid)
            || NSRIObjectIdentifiers.id_aria256_cbc.equals(oid))
        {
            return "ARIA";
        }
        if (NTTObjectIdentifiers.id_camellia128_cbc.equals(oid)
            || NTTObjectIdentifiers.id_camellia192_cbc.equals(oid)
            || NTTObjectIdentifiers.id_camellia256_cbc.equals(oid))
        {
            return "Camellia";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA1.equals(oid))
        {
            return "HmacSHA1";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA224.equals(oid))
        {
            return "HmacSHA224";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(oid))
        {
            return "HmacSHA256";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA384.equals(oid))
        {
            return "HmacSHA384";
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(oid))
        {
            return "HmacSHA512";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_224.equals(oid))
        {
            return "HmacSHA3-224";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_256.equals(oid))
        {
            return "HmacSHA3-256";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_384.equals(oid))
        {
            return "HmacSHA3-384";
        }
        if (NISTObjectIdentifiers.id_hmacWithSHA3_512.equals(oid))
        {
            return "HmacSHA3-512";
        }
        // Unrecognised OID — fall back to its string form so callers can
        // still retrieve the key bytes via SecretKeySpec.
        return oid.getId();
    }

    static ASN1Encodable getContent(ContentInfo contentInfo) throws IOException
    {
        ASN1Encodable content = contentInfo.getContent();
        if (content == null)
        {
            throw new ASN1ParsingException("ContentInfo content missing");
        }

        return content;
    }

    static byte[] getContentOctets(ContentInfo contentInfo) throws IOException
    {
        return ASN1OctetString.getInstance(getContent(contentInfo)).getOctets();
    }

    static ASN1OctetString getEncryptedContent(EncryptedData encryptedData) throws IOException
    {
        ASN1OctetString content = encryptedData.getContent();
        if (content == null)
        {
            throw new ASN1ParsingException("EncryptedContentInfo content missing");
        }

        return content;
    }

    static int validateIterationCount(BigInteger ic)
    {
        if (ic.signum() < 0)
        {
            throw new IllegalStateException("negative iteration count found");
        }
        if (ic.bitLength() > 31)
        {
            throw new IllegalStateException("iteration counts >= 2^31 are not suppported");
        }

        BigInteger max = Properties.asBigInteger(Properties.PKCS12_MAX_IT_COUNT);
        if (max == null)
        {
            max = DEFAULT_MAX_IT_COUNT;
        }

        if (ic.compareTo(max) > 0)
        {
            throw new IllegalStateException("iteration count " + ic + " greater than " + max);
        }

        return BigIntegers.intValueExact(ic);
    }
}
