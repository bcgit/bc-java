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
 * Utility method for accessing system properties.
 */
public class Properties
{
    /**
     * If set the provider will attempt, where possible, to behave the same way as the oracle one.
     */
    public static final String EMULATE_ORACLE = "org.bouncycastle.emulate.oracle";

    // Mirrored from the base org.bouncycastle.util.Properties so the down-ported
    // classes that reference them compile in the jdk1.4 build. Keep in step with base.
    public static final String PKCS12_IGNORE_USELESS_PASSWD = "org.bouncycastle.pkcs12.ignore_useless_passwd";
    public static final String PKCS12_MAX_IT_COUNT = "org.bouncycastle.pkcs12.max_it_count";
    public static final String BKS_MAX_IT_COUNT = "org.bouncycastle.bks.max_it_count";
    public static final String X509_CRL_CACHE_TTL = "org.bouncycastle.x509.crl_cache_ttl";
    public static final String X509_ENABLE_CRLDP = "org.bouncycastle.x509.enableCRLDP";
    public static final String PKCS12_ALLOW_SUN_SECRET_KEYS = "org.bouncycastle.pkcs12.allow_sun_secret_keys";
    public static final String PKCS1_STRICT_DIGESTINFO = "org.bouncycastle.pkcs1.strict_digestinfo";
    public static final String JSSE_HOSTNAME_CHECK_CN_FALLBACK = "org.bouncycastle.jsse.hostname_check_cn_fallback";
    public static final String DRBG_EFFECTIVE_256BITS_ENTROPY = "org.bouncycastle.drbg.effective_256bits_entropy";
    public static final String DRBG_ENTROPY_SOURCE = "org.bouncycastle.drbg.entropysource";
    public static final String DRBG_ENTROPY_THREAD = "org.bouncycastle.drbg.entropy_thread";
    public static final String DRBG_GATHER_PAUSE_SECS = "org.bouncycastle.drbg.gather_pause_secs";
    public static final String ASN1_ALLOW_NON_DER_TIME = "org.bouncycastle.asn1.allow_non_der_time";
    public static final String ASN1_MAX_CONS_DEPTH = "org.bouncycastle.asn1.max_cons_depth";
    public static final String ASN1_MAX_LIMIT = "org.bouncycastle.asn1.max_limit";
    public static final String DH_MAX_SIZE = "org.bouncycastle.dh.max_size";
    public static final String DSA_MAX_SIZE = "org.bouncycastle.dsa.max_size";
    public static final String BCFKS_MAX_IT_COUNT = "org.bouncycastle.bcfks.max_it_count";
    public static final String BCFKS_MAX_SCRYPT_MEMORY = "org.bouncycastle.bcfks.max_scrypt_memory";
    public static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";
    public static final String PBE_MAX_SCRYPT_MEMORY = "org.bouncycastle.pbe.max_scrypt_memory";
    public static final String PKMAC_MAX_ITERATION_COUNT = "org.bouncycastle.pkmac.max_iteration_count";
    public static final String X509_MAX_POLICY_NODES = "org.bouncycastle.x509.max_policy_nodes";
    public static final String X509_ALLOW_LENIENT_RFC822_NAME = "org.bouncycastle.x509.allow_lenient_rfc822_name";
    public static final String GCM_ALLOW_SHORT_TAGS = "org.bouncycastle.gcm.allow_short_tags";
    public static final String BKS_ENABLE_V1 = "org.bouncycastle.bks.enable_v1";

    /**
     * Opt in to the relaxed directoryName name-constraint matching required by GSMA SGP.22 v2.5
     * (Remote SIM Provisioning). Looser than RFC 5280 7.1, so defaults to off. See github #2327.
     */
    public static final String X509_SGP22_NAME_CONSTRAINTS = "org.bouncycastle.x509.sgp22_name_constraints";

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
            String p = getPropertyValue(propertyName);

            return "true".equalsIgnoreCase(p);
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
                return "true".equalsIgnoreCase(value);
            }
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
                //if (localProps.isEmpty())
                //{
                    //threadProperties.remove();
                //}

                return "true".equalsIgnoreCase(p);
            }
        }

        return false;
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

    public static int asInteger(String propertyName, int defaultValue)
    {
        String p = getPropertyValue(propertyName);

        if (p != null)
        {
            return Integer.parseInt(p);
        }

        return defaultValue;
    }
    
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
