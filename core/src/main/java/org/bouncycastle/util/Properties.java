package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Utility method for accessing properties values - properties can be set in java.security,
 * thread local, and system properties. They are checked for in the same order with
 * checking stopped as soon as a value is found.
 */
public class Properties
{
    /**
     * If set the provider will attempt, where possible, to behave the same way as the oracle one.
     */
    public static final String EMULATE_ORACLE = "org.bouncycastle.emulate.oracle";

    /**
     * A PKCS12 file which does not require a password will normally throw an exception if a password
     * is provided. Setting PKCS12_IGNORE_USELESS_PASSWD to "true" will result in the provider ignoring a
     * password if one is provided and not required.
     */
    public static final String PKCS12_IGNORE_USELESS_PASSWD = "org.bouncycastle.pkcs12.ignore_useless_passwd";

    /**
     * If set, a PKCS12 file with a larger iteration count on PBE processing will rejected.
     */
    public static final String PKCS12_MAX_IT_COUNT = "org.bouncycastle.pkcs12.max_it_count";

    /**
     * Maximum time, in seconds, that a downloaded CRL is cached by the internal CrlCache used
     * by the CertPath validator and X509RevocationChecker. When set to a positive value, cached
     * entries are evicted whichever expires sooner: the configured TTL or the CRL's own
     * {@code nextUpdate}. Default (or 0) preserves the legacy behaviour of evicting only when
     * {@code nextUpdate} has passed.
     */
    public static final String X509_CRL_CACHE_TTL = "org.bouncycastle.x509.crl_cache_ttl";

    /**
     * If set to "true", the BC CertPath validator and X509RevocationChecker will attempt to
     * download CRLs over the network using URIs from each certificate's CRL Distribution Points
     * extension when no PKIXCRLStore on the supplied PKIXParameters can satisfy the lookup.
     * Default (unset / "false") preserves the legacy behaviour of relying entirely on caller-supplied
     * CertStore / PKIXCRLStore registrations &mdash; "No CRLs found for issuer ..." is the result
     * when the caller hasn't registered a store and this property is off.
     */
    public static final String X509_ENABLE_CRLDP = "org.bouncycastle.x509.enableCRLDP";

    /**
     * If set to "true", the BC PKCS#12 KeyStore will additionally accept (on load only)
     * SafeBags of type secretBag that use SunJCE's non-standard nested encoding —
     * a SecretBag whose secretTypeId is pkcs8ShroudedKeyBag and whose secretValue is
     * an EncryptedPrivateKeyInfo wrapping a PKCS#8 PrivateKeyInfo carrying the raw
     * secret-key bytes. Off by default; the BC keystore always writes the standards
     * compliant RFC 7292 sec. 4.2.5 form regardless.
     */
    public static final String PKCS12_ALLOW_SUN_SECRET_KEYS = "org.bouncycastle.pkcs12.allow_sun_secret_keys";

    /**
     * If set to "true", RSA PKCS#1 v1.5 signature verification rejects DigestInfo
     * encodings whose AlgorithmIdentifier omits the {@code NULL} parameters octets
     * required by RFC 8017 sec. 9.2 / Appendix A.2.4. By default (or "false") the
     * verifier falls back to accepting that two-byte-shorter encoding for compatibility
     * with implementations that have historically produced it; setting this property
     * to "true" disables the fallback so only strictly RFC-compliant signatures verify
     * (github #2273). Affects both the BC JCE provider's
     * {@code DigestSignatureSpi} and the lightweight {@code RSADigestSigner}.
     */
    public static final String PKCS1_STRICT_DIGESTINFO = "org.bouncycastle.pkcs1.strict_digestinfo";

    /**
     * Opt-in to the legacy "use the subject CN as a fallback identifier" behaviour
     * in the BC JSSE provider's hostname verifier. When the property is set to
     * "true", a TLS server certificate that carries no SAN dNSName entries falls
     * back to the most specific {@code commonName} attribute of the subject DN —
     * this matches SunJSSE and historical OpenSSL behaviour.
     * <p>
     * Default ("false" / unset) follows RFC 9525 sec. 6.3 (which deprecates CN-based
     * identity for TLS) and CAB Forum Baseline Requirements 7.1.4.2 (which requires
     * SAN dNSName entries for publicly-trusted TLS server certs). It also closes a
     * Name-Constraint bypass surface (the 2026-03 cross-implementation X.509 audit):
     * a constrained intermediate CA can omit dNSName SAN entries entirely so the
     * path validator's Name-Constraint dNSName checks never fire, then embed an
     * attacker-controlled hostname in CN — the JSSE verifier would have accepted
     * the connection. Setting the property "false" (or leaving it unset) disables
     * this fallback path and the JSSE verifier rejects any cert that doesn't carry
     * a matching SAN identifier.
     */
    public static final String JSSE_HOSTNAME_CHECK_CN_FALLBACK = "org.bouncycastle.jsse.hostname_check_cn_fallback";

    /**
     * Effective bits-of-entropy assumed per real bit when the BC DRBG provider seeds for
     * a 256-bit security level — used to compute the byte-oriented samples requested from
     * the underlying entropy source. Defaults to 282 bits (about 0.9 effective bits per
     * raw bit) and is rounded up to the next whole byte.
     */
    public static final String DRBG_EFFECTIVE_256BITS_ENTROPY = "org.bouncycastle.drbg.effective_256bits_entropy";

    /**
     * Fully-qualified name of an {@code EntropySourceProvider} class to use as the BC DRBG
     * provider's seed source. When set, the named class is loaded reflectively and
     * instantiated in place of the platform default. When unset, the BC DRBG falls back
     * to the configured {@code securerandom.source} or its own background entropy thread.
     */
    public static final String DRBG_ENTROPY_SOURCE = "org.bouncycastle.drbg.entropysource";

    /**
     * If set to "true", the BC DRBG provider runs a background thread that samples the
     * platform entropy source on a fixed schedule and feeds the DRBG, rather than
     * blocking on a fresh sample at each reseed.
     */
    public static final String DRBG_ENTROPY_THREAD = "org.bouncycastle.drbg.entropy_thread";

    /**
     * Pause, in seconds, between background entropy-thread samples (see
     * {@link #DRBG_ENTROPY_THREAD}). Parsed as an integer; absent or non-positive values
     * use the implementation default.
     */
    public static final String DRBG_GATHER_PAUSE_SECS = "org.bouncycastle.drbg.gather_pause_secs";

    /**
     * Controls whether an ASN.1 {@code UTCTime} / {@code GeneralizedTime} carrying non-DER
     * contents may be serialized through a {@code DEROutputStream}. Reading is always
     * lenient: a wire value that is valid ASN.1 but not valid DER - for example a UTCTime
     * without the seconds element ("YYMMDDHHMMZ"), a time terminated with a "+hhmm"/"-hhmm"
     * offset rather than "Z", or a GeneralizedTime fraction carrying trailing zeros - parses
     * without complaint into a usable {@code ASN1UTCTime} / {@code ASN1GeneralizedTime}.
     * <p>
     * Default (unset or "true") preserves BC's historical pass-through: such a primitive may
     * be re-emitted unchanged via either BER or DER. Setting this property to "false"
     * enforces the DER restrictions of X.690 sec. 11.7 / 11.8 (and hence the RFC 5280
     * sec. 4.1.2.5 profile, which requires seconds and Zulu) on the DER write side: the
     * primitive's {@code toDERObject()} throws an {@code IllegalStateException} if it would
     * emit non-conformant content, so any attempt to write it to a {@code DEROutputStream}
     * fails (github #1973 / #1986). BER serialization is unaffected. Programmatically
     * constructing a time from a {@code Date} always produces DER content, so this setting
     * only matters for primitives whose contents arrived non-conformant from the wire.
     */
    public static final String ASN1_ALLOW_NON_DER_TIME = "org.bouncycastle.asn1.allow_non_der_time";

    /**
     * Maximum depth of nested constructed ASN.1 objects the parser will descend before failing
     * with "maximum nested construction level reached", guarding against stack exhaustion from
     * deeply nested crafted input. Read as an integer; default 64.
     */
    public static final String ASN1_MAX_CONS_DEPTH = "org.bouncycastle.asn1.max_cons_depth";

    /**
     * Overrides the maximum length accepted for a single definite-length ASN.1 object read from a
     * stream whose length is not otherwise known. The value is a byte count and may carry a trailing
     * 'k', 'm' or 'g' multiplier (e.g. "16m"); when unset the limit falls back to the available heap
     * size. Can also be set per stream via the ASN1InputStream(InputStream, int) constructor.
     */
    public static final String ASN1_MAX_LIMIT = "org.bouncycastle.asn1.max_limit";

    /**
     * Upper bound (in bits) on the prime modulus p accepted when validating an imported
     * Diffie-Hellman public key. Validation performs a modular exponentiation / Legendre
     * computation whose cost is super-linear in the size of p, so an unbounded p taken from a
     * crafted key encoding would turn key import into a CPU-exhaustion denial of service. The
     * default (16384) is the analogue of {@code org.bouncycastle.rsa.max_size} and is well above
     * any standardised DH group. Read via {@link #asInteger(String, int)}.
     */
    public static final String DH_MAX_SIZE = "org.bouncycastle.dh.max_size";

    /**
     * Upper bound (in bits) on the prime modulus p accepted when validating an imported DSA
     * public key. As with {@link #DH_MAX_SIZE}, validation runs a modular exponentiation whose
     * cost grows super-linearly in the size of p, so an unbounded p from a crafted encoding is an
     * import-time CPU-exhaustion vector. Default 16384. Read via {@link #asInteger(String, int)}.
     */
    public static final String DSA_MAX_SIZE = "org.bouncycastle.dsa.max_size";

    /**
     * Upper bound on the PBKDF2 iteration count honoured when deriving the integrity-MAC key of a
     * BCFKS keystore during load. The KDF runs on parameters taken from the (not-yet-verified)
     * keystore, so an unbounded iteration count is a pre-integrity CPU-exhaustion vector. Default
     * 5,000,000 (the BCFKS writer uses ~51,200). Read via {@link #asInteger(String, int)}.
     */
    public static final String BCFKS_MAX_IT_COUNT = "org.bouncycastle.bcfks.max_it_count";

    /**
     * Upper bound, in bytes, on the working memory (~128 * N * r) of the scrypt KDF honoured when
     * deriving the integrity-MAC key of a BCFKS keystore during load. As with
     * {@link #BCFKS_MAX_IT_COUNT} the scrypt cost parameters are taken from the not-yet-verified
     * keystore, so an unbounded cost is a pre-integrity memory-exhaustion vector. Default
     * 1073741824 (1 GiB); the BCFKS writer uses N=16384, r=8 (~16 MiB). Read via
     * {@link #asInteger(String, int)}.
     */
    public static final String BCFKS_MAX_SCRYPT_MEMORY = "org.bouncycastle.bcfks.max_scrypt_memory";

    /**
     * Upper bound on the PBKDF2 iteration count honoured when decrypting a PBES2-protected
     * PKCS#8 / PEM private key. The key-derivation parameters travel inside the (unauthenticated)
     * encrypted-key container, so an unbounded count makes decrypting attacker-supplied key
     * material a CPU-exhaustion vector. Default 10,000,000, generous enough for deliberately
     * strong settings. Read via {@link #asInteger(String, int)}.
     */
    public static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";

    /**
     * Upper bound, in bytes, on the scrypt working memory (~128 * N * r) honoured when decrypting
     * a PBES2-protected PKCS#8 / PEM private key. As with {@link #PBE_MAX_ITERATION_COUNT} the
     * scrypt cost travels in the unauthenticated container, so an unbounded cost is a
     * memory-exhaustion vector. Default 1073741824 (1 GiB). Read via {@link #asInteger(String, int)}.
     */
    public static final String PBE_MAX_SCRYPT_MEMORY = "org.bouncycastle.pbe.max_scrypt_memory";

    /**
     * Upper bound on the RFC 4211 PKMAC / CMP password-based-MAC iteration count honoured when no
     * explicit ceiling was supplied to {@link org.bouncycastle.cert.crmf.PKMACBuilder}. The count
     * travels in the (unauthenticated) PBMParameter of an incoming CMP message and drives an
     * iterated hash, so an unbounded count makes verifying an attacker-supplied message a
     * CPU-exhaustion vector. Default 10,000,000, generous enough for any legitimate setting. Read
     * via {@link #asInteger(String, int)}.
     */
    public static final String PKMAC_MAX_ITERATION_COUNT = "org.bouncycastle.pkmac.max_iteration_count";

    /**
     * Upper bound on the total number of valid-policy-tree nodes retained (across all depth
     * levels) during PKIX certification-path validation. Certificate policy mapping combined with
     * the anyPolicy expansion of RFC 5280 6.1.3/6.1.4 can grow the tree multiplicatively per
     * certificate, so a crafted chain that still chains to a trust anchor could drive the validator
     * into exponential memory/CPU consumption -- a denial of service of the class of CVE-2023-0464.
     * The tree size is checked once per certificate and validation is aborted with a
     * CertPathValidatorException once it exceeds this bound. The default (8192) is far above any
     * legitimate policy tree (a real chain produces a handful of nodes) and is configurable for
     * unusual deployments. Read via {@link #asInteger(String, int)}.
     */
    public static final String X509_MAX_POLICY_NODES = "org.bouncycastle.x509.max_policy_nodes";

    /**
     * Opt in to the relaxed directoryName name-constraint matching required by GSMA SGP.22 v2.5
     * (Remote SIM Provisioning), sections 4.5.2.1.0.2 / 4.5.2.1.0.3. When set, a permitted-subtree
     * RDN is satisfied by any matching subject RDN regardless of position, additional subject
     * attributes beyond those named in the subtree are tolerated, and a serialNumber RDN is matched
     * with a startsWith comparison wherever it appears. This is deliberately looser than the
     * contiguous-prefix DN matching mandated by RFC 5280 7.1, so it defaults to off and must be
     * enabled explicitly; BC's default validation remains RFC 5280 strict. See github #2327.
     * Read via {@link #isOverrideSet(String)}.
     */
    public static final String X509_SGP22_NAME_CONSTRAINTS = "org.bouncycastle.x509.sgp22_name_constraints";

    /**
     * Fall back to the legacy lenient parsing of rfc822Name values in X.509 name-constraint checks. By
     * default the validator is strict about rfc822Name conformance; today that means a tested rfc822Name
     * with more than one '@' is rejected as ambiguous when email constraints apply (RFC 5321 sec. 4.1.2
     * allows '@' inside a quoted local part, so the domain is not simply the text after the first '@',
     * and a wrong split could evade a constraint). When this property is set, that strictness (and any
     * future rfc822Name conformance strictness) is disabled and the historical permissive parsing is used
     * instead. Strict is the default; set this only to restore the old behaviour. This is a safety valve,
     * not a recommended mode. Read via {@link #isOverrideSet(String)}.
     */
    public static final String X509_ALLOW_LENIENT_RFC822_NAME = "org.bouncycastle.x509.allow_lenient_rfc822_name";

    /**
     * Opt in to short AEAD authentication tags for AES-GCM parameters. RFC 5084 constrains the
     * AES-GCM ICV (tag) length carried in {@code GCMParameters} to 12..16 octets (96..128 bits), and
     * BC enforces that by default. When this property is set, {@code GCMParameters} additionally
     * accepts tags down to the NIST SP 800-38D minimum of 4 octets (32 bits; SP 800-38D sec. 5.2.1.2
     * permits a 32-bit tag for limited applications). Short tags weaken integrity protection, so this
     * defaults to off and must be enabled explicitly; anything below 4 octets or above 16 octets is
     * still rejected. Read via {@link #isOverrideSet(String)}.
     */
    public static final String GCM_ALLOW_SHORT_TAGS = "org.bouncycastle.gcm.allow_short_tags";

    /**
     * Opt in to handling legacy version 0/1 BKS keystores. Those stores derive the HMAC integrity
     * key at only the digest size in bits (a 16-bit key for SHA-1; CVE-2018-5382), which is
     * brute-forceable offline, so by default the default {@code BKS} keystore type refuses to load
     * them and only writes the current version 2 format. Set this property to read or create the
     * weak legacy format (e.g. to migrate an old store); it also gates registration of the separate
     * {@code BKS-V1} keystore type. Read via {@link #isOverrideSet(String)}.
     */
    public static final String BKS_ENABLE_V1 = "org.bouncycastle.bks.enable_v1";

    /**
     * Upper bound on the PKCS#12-PBE iteration count honoured when loading a BKS keystore. The
     * count drives the integrity-MAC key derivation in {@code BcKeyStoreSpi.engineLoad} (and the
     * per-entry sealed-key decryption), and is read from the (not-yet-verified) keystore ahead of
     * the HMAC integrity check, so an unbounded value is a pre-integrity CPU-exhaustion vector -
     * the analogue of {@link #BCFKS_MAX_IT_COUNT} / {@link #PKCS12_MAX_IT_COUNT} for the BKS
     * format (the sibling UBER store already caps its own count). Default 1048576 (1 << 20); the
     * BKS writer uses ~1024-2047. Read via {@link #asInteger(String, int)}.
     */
    public static final String BKS_MAX_IT_COUNT = "org.bouncycastle.bks.max_it_count";

    private Properties()
    {
    }

    private static final ThreadLocal threadProperties = new ThreadLocal();

    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
    public static boolean isOverrideSet(String propertyName)
    {
        try
        {
            return isSetTrue(getPropertyValue(propertyName));
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Return whether a particular override has been set to true.
     *
     * @param propertyName the property name for the override.
     * @return true if the property is set to "true", false otherwise.
     */
   public static boolean isOverrideSet(String propertyName, boolean defIsTrue)
   {
       try
       {
           String value = getPropertyValue(propertyName);
           if (value == null)
           {
               return defIsTrue;
           }
           else
           {
               return isSetTrue(value);
           }
       }
       catch (AccessControlException e)
       {
           return false;
       }
   }

    /**
     * Return whether a particular override has been set to false.
     *
     * @param propertyName the property name for the override.
     * @param isTrue true if the override should be true, false otherwise.
     * @return true if the property is set to the value of isTrue, false otherwise.
     */
    public static boolean isOverrideSetTo(String propertyName, boolean isTrue)
    {
        try
        {
            String propertyValue = getPropertyValue(propertyName);
            if (isTrue)
            {
                return isSetTrue(propertyValue);
            }
            return isSetFalse(propertyValue);
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Enable the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @param enable true if the override should be enabled, false if it should be disabled.
     * @return true if the override was already set true, false otherwise.
     */
    public static boolean setThreadOverride(String propertyName, boolean enable)
    {
        boolean isSet = isOverrideSet(propertyName);

        Map localProps = (Map)threadProperties.get();
        if (localProps == null)
        {
            localProps = new HashMap();

            threadProperties.set(localProps);
        }

        localProps.put(propertyName, enable ? "true" : "false");

        return isSet;
    }

    /**
     * Remove any value for the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @return true if the override was already set true in thread local, false otherwise.
     */
    public static boolean removeThreadOverride(String propertyName)
    {
        Map localProps = (Map)threadProperties.get();
        if (localProps != null)
        {
            String p = (String)localProps.remove(propertyName);
            if (p != null)
            {
                if (localProps.isEmpty())
                {
                    threadProperties.remove();
                }

                return "true".equals(Strings.toLowerCase(p));
            }
        }

        return false;
    }

    /**
     * Return propertyName as an integer, defaultValue used if not defined.
     *
     * @param propertyName name of property.
     * @param defaultValue integer to return if property not defined.
     * @return value of property, or default if not found, as an int.
     */
    public static int asInteger(String propertyName, int defaultValue)
    {
        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            return Integer.parseInt(p);
        }

        return defaultValue;
    }

    /**
     * Return propertyName as a BigInteger.
     *
     * @param propertyName name of property.
     * @return value of property as a BigInteger, null if not defined.
     */
    public static BigInteger asBigInteger(String propertyName)
    {
        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            return new BigInteger(p);
        }

        return null;
    }

    public static Set<String> asKeySet(String propertyName)
    {
        Set<String> set = new HashSet<String>();

        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            StringTokenizer sTok = new StringTokenizer(p, ",");
            while (sTok.hasMoreElements())
            {
                set.add(Strings.toLowerCase(sTok.nextToken()).trim());
            }
        }

        return Collections.unmodifiableSet(set);
    }

    /**
     * Return the String value of the property propertyName. Property valuation
     * starts with java.security, then thread local, then system properties.
     *
     * @param propertyName name of property.
     * @return value of property as a String, null if not defined.
     */
    public static String getPropertyValue(final String propertyName)
    {
        String val = (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return Security.getProperty(propertyName);
            }
        });
        if (val != null)
        {
            return val;
        }

        Map localProps = (Map)threadProperties.get();
        if (localProps != null)
        {
            String p = (String)localProps.get(propertyName);
            if (p != null)
            {
                return p;
            }
        }

        return (String)AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                return System.getProperty(propertyName);
            }
        });
    }

    public static String getPropertyValue(final String propertyName,  String defValue)
    {
        String rv = getPropertyValue(propertyName);

        if (rv == null)
        {
            return defValue;
        }

        return rv;
    }

    private static boolean isSetFalse(String p)
    {
        if (p == null || p.length() != 5)
        {
            return false;
        }

        return (p.charAt(0) == 'f' || p.charAt(0) == 'F')
            && (p.charAt(1) == 'a' || p.charAt(1) == 'A')
            && (p.charAt(2) == 'l' || p.charAt(2) == 'L')
            && (p.charAt(3) == 's' || p.charAt(3) == 'S')
            && (p.charAt(4) == 'e' || p.charAt(4) == 'E');
    }

    private static boolean isSetTrue(String p)
    {
        if (p == null || p.length() != 4)
        {
            return false;
        }

        return (p.charAt(0) == 't' || p.charAt(0) == 'T')
            && (p.charAt(1) == 'r' || p.charAt(1) == 'R')
            && (p.charAt(2) == 'u' || p.charAt(2) == 'U')
            && (p.charAt(3) == 'e' || p.charAt(3) == 'E');
    }
}
