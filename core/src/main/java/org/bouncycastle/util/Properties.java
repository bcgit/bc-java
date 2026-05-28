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
