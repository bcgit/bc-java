package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
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
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
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
     * The PBE iteration count used when writing a PKCS#12 file, and half the count used for its
     * integrity MAC. Just under the OWASP figure of 600,000 for PBKDF2-HMAC-SHA256.
     * <p>
     * <b>Do not raise this to 600,000 or more without testing on Windows:</b> Windows currently
     * reports an error importing a PKCS#12 file written with an iteration count of 600,000 or
     * greater. That limit may change in later Windows releases, so recheck it before moving this.
     */
    static final int DEFAULT_STORE_IT_COUNT = 599000;

    /**
     * Largest count {@link Properties#PKCS12_STORE_IT_COUNT} may name. Half of
     * {@link #DEFAULT_MAX_IT_COUNT} so that the doubled MAC count still passes
     * {@link #validateIterationCount(BigInteger)} on load: a file BC writes must be one BC can
     * read back with the read-side cap left at its default.
     */
    private static final int MAX_STORE_IT_COUNT = 2500000;

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

    // The RFC 9579 sec. 9 floor for a PBMAC1 MAC key; see validateMacKeyLength, which is the only
    // thing that applies it - a PBES2 content-encryption keyLength legitimately goes below it.
    private static final BigInteger MIN_MAC_KEY_LENGTH = BigInteger.valueOf(20);
    // the PBKDF2 count a PBMAC1 MAC is written with by default, and the floor for one it inherits
    private static final int DEFAULT_MAC_KDF_IT_COUNT = 1 << 16;
    // the shortest MAC salt written, whatever a loaded file declared - PKCS#12's traditional size
    private static final int MIN_MAC_SALT_LENGTH = 8;
    // Any keyLength beyond this is rejected as abusive, whatever it is sizing.
    private static final BigInteger MAX_KEY_LENGTH = BigInteger.valueOf(1024);

    static int validateKeyLength(BigInteger keyLength)
    {
        // As with the iteration count: this arrives in a PFX whose MAC has not been checked yet
        // and sizes the PBKDF2 output, so bound it before deriving. It is also multiplied by 8 at
        // the call sites, which overflows to a negative bit count for a large enough value.
        if (keyLength == null || keyLength.signum() <= 0)
        {
            throw new IllegalStateException("keyLength must be positive");
        }

        if (keyLength.compareTo(MAX_KEY_LENGTH) > 0)
        {
            throw new IllegalStateException("keyLength " + keyLength + " greater than " + MAX_KEY_LENGTH);
        }

        return BigIntegers.intValueExact(keyLength);
    }

    /**
     * Validate a PBKDF2 keyLength that will size a <b>PBMAC1 MAC key</b>. As
     * {@link #validateKeyLength(BigInteger)}, plus the floor RFC 9579 sec. 9 asks for: "It's
     * RECOMMENDED to reject any KDF parameters that specify key lengths less than 20 octets." A MAC
     * key of one or two octets is brute-forceable, so a PFX declaring one would have its integrity
     * MAC checked against a key an attacker can guess without knowing the password. Sec. 5 has the
     * length SHOULD match the HMAC output size, so no conforming file comes near the floor.
     * <p>
     * This is deliberately separate from {@link #validateKeyLength(BigInteger)}, which also bounds
     * the PBES2 <i>content-encryption</i> keyLength - where 16 octets (AES-128) is legal and BC
     * writes it itself. The upper bound stays at 1024 rather than the HMAC output size for the
     * mirror-image reason: BC's PKCS12-PBMAC1 keystore asked for a 256-octet MAC key up to release
     * 1.86, so a cap at the output size would refuse files BC itself produced.
     *
     * @param keyLength the keyLength from the wire.
     * @return the validated keyLength in bytes.
     * @throws IllegalStateException if the keyLength is absent, not positive, below 20 octets, or
     *         larger than the maximum supported.
     */
    /**
     * Return the PBKDF2 iteration count to write a PBMAC1 MAC with, given the count a loaded file
     * carried. A file keeps its own count where that is at least the count this release would
     * choose for itself, and is raised to that otherwise: the count is the work factor protecting
     * the file being written, and the file being re-stored is no longer the one the count was
     * chosen for. Reading is unaffected - a file's MAC can only be verified with the count it was
     * made with, whatever that is.
     *
     * @param iterationCount the iteration count the loaded file's PBKDF2 parameters carried.
     * @return the count to write with.
     */
    /**
     * Return the MAC AlgorithmIdentifier to write a file with, given the one the store holds -
     * which after a load is the one the loaded file carried.
     * <p>
     * For PBMAC1 the PBKDF2 salt is generated afresh here for every write: a salt is
     * per-derivation, so neither a salt a loaded file carried nor one an earlier write of the same
     * store used may be written again. The rest of the shape - the PRF, the key length, the
     * authentication scheme and the iteration count - is kept, so a file keeps the form it arrived
     * in, with the count raised by {@link #getMacKdfIterationCount(BigInteger)} if the file asked
     * for less than this release writes itself. Any other MAC algorithm is returned unchanged: its
     * salt lives in the MacData, which both stores generate per write.
     *
     * @param macAlgorithm the MAC AlgorithmIdentifier the store holds.
     * @param random source of randomness for a new salt.
     * @return the AlgorithmIdentifier to MAC the file with.
     */
    static AlgorithmIdentifier getWriteMacAlgorithm(AlgorithmIdentifier macAlgorithm, SecureRandom random)
    {
        if (!PKCSObjectIdentifiers.id_PBMAC1.equals(macAlgorithm.getAlgorithm()))
        {
            return macAlgorithm;
        }

        int itCount = getPbkdf2IterationCount();
        // RFC 9579 sec. 5: the derived key SHOULD be the size of the HMAC output, which is 64 for
        // the HMAC-SHA-512 auth scheme below. Releases up to 1.86 asked for 256 here; those files
        // still verify, since the length is read back from the file.
        int keyLength = 64;
        AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256);
        AlgorithmIdentifier authScheme = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512);

        if (macAlgorithm.getParameters() != null)
        {
            PBMAC1Params loaded = PBMAC1Params.getInstance(macAlgorithm.getParameters());

            if (PKCSObjectIdentifiers.id_PBKDF2.equals(loaded.getKeyDerivationFunc().getAlgorithm()))
            {
                PBKDF2Params loadedKdf = PBKDF2Params.getInstance(loaded.getKeyDerivationFunc().getParameters());

                itCount = getMacKdfIterationCount(loadedKdf.getIterationCount());
                if (loadedKdf.getKeyLength() != null)
                {
                    keyLength = validateMacKeyLength(loadedKdf.getKeyLength());
                }
                prf = loadedKdf.getPrf();
                authScheme = loaded.getMessageAuthScheme();
            }
        }

        byte[] pbSalt = new byte[32];

        random.nextBytes(pbSalt);

        AlgorithmIdentifier keyDevFunc = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
            new PBKDF2Params(pbSalt, itCount, keyLength, prf));

        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, new PBMAC1Params(keyDevFunc, authScheme));
    }

    static int getMacKdfIterationCount(BigInteger iterationCount)
    {
        return Math.max(validateIterationCount(iterationCount), getPbkdf2IterationCount());
    }

    /**
     * Return the PBKDF2 iteration count to write a PBMAC1 MAC with, from
     * {@link Properties#PKCS12_PBKDF2_IT_COUNT}, which also floors a count taken from a loaded
     * file. A value outside the range {@link #getStoreIterationCount()} accepts is ignored.
     *
     * @return the configured count, or 65,536.
     */
    static int getPbkdf2IterationCount()
    {
        int itCount = Properties.asInteger(Properties.PKCS12_PBKDF2_IT_COUNT, DEFAULT_MAC_KDF_IT_COUNT);

        if (itCount < 1 || itCount > MAX_STORE_IT_COUNT)
        {
            return DEFAULT_MAC_KDF_IT_COUNT;
        }

        return itCount;
    }

    /**
     * Return the length of the MacData salt to write, given the length a loaded file declared.
     * A file keeps its own length where that is at least {@link #MIN_MAC_SALT_LENGTH}, so a file
     * from another implementation round trips, but a file declaring no salt at all - or one too
     * short to be one - does not hand that on to a file written here.
     *
     * @param saltLength the MAC salt length the loaded file declared.
     * @return the length to write.
     */
    static int getMacSaltLength(int saltLength)
    {
        return Math.max(saltLength, MIN_MAC_SALT_LENGTH);
    }

    static int validateMacKeyLength(BigInteger keyLength)
    {
        int length = validateKeyLength(keyLength);

        if (keyLength.compareTo(MIN_MAC_KEY_LENGTH) < 0)
        {
            throw new IllegalStateException("keyLength " + keyLength + " less than " + MIN_MAC_KEY_LENGTH);
        }

        return length;
    }

    /**
     * The PBE iteration count to write with, {@link #DEFAULT_STORE_IT_COUNT} unless
     * {@link Properties#PKCS12_STORE_IT_COUNT} names a usable value. A value outside
     * 1 .. {@link #MAX_STORE_IT_COUNT} is ignored, so a mistyped property fails towards
     * the default rather than towards a file with no PBE work in it. (A value that is not
     * a number at all still throws out of {@link Properties#asInteger(String, int)}.)
     */
    static int getStoreIterationCount()
    {
        int itCount = Properties.asInteger(Properties.PKCS12_STORE_IT_COUNT, DEFAULT_STORE_IT_COUNT);

        if (itCount < 1 || itCount > MAX_STORE_IT_COUNT)
        {
            return DEFAULT_STORE_IT_COUNT;
        }

        return itCount;
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
