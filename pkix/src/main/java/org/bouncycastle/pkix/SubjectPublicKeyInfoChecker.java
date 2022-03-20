package org.bouncycastle.pkix;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9FieldID;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.Primes;
import org.bouncycastle.util.Strings;

/**
 * A checker for vetting subject public keys based on the direct checking of the ASN.1
 */
public class SubjectPublicKeyInfoChecker
{
    private static final Cache validatedQs = new Cache();
    private static final Cache validatedMods = new Cache();

    // Hexadecimal value of the product of the 131 smallest odd primes from 3 to 743
    private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger(
        "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f"
            + "73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2"
            + "ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8"
            + "f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f",
        16);

    private static final BigInteger ONE = BigInteger.valueOf(1);

    public static void checkInfo(SubjectPublicKeyInfo pubInfo)
    {
        ASN1ObjectIdentifier algorithm = pubInfo.getAlgorithm().getAlgorithm();
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm))
        {
            X962Parameters params = X962Parameters.getInstance(pubInfo.getAlgorithm().getParameters());
            if (params.isImplicitlyCA() || params.isNamedCurve())
            {
                return;
            }

            ASN1Sequence ecParameters = ASN1Sequence.getInstance(params.getParameters());
            X9FieldID fieldID = X9FieldID.getInstance(ecParameters.getObjectAt(1));
            if (fieldID.getIdentifier().equals(X9FieldID.prime_field))
            {
                BigInteger q = ASN1Integer.getInstance(fieldID.getParameters()).getValue();

                if (validatedQs.contains(q))
                {
                    return;
                }
                
                int maxBitLength = Properties.asInteger("org.bouncycastle.ec.fp_max_size", 1042); // 2 * 521
                int certainty = Properties.asInteger("org.bouncycastle.ec.fp_certainty", 100);

                int qBitLength = q.bitLength();
                if (maxBitLength < qBitLength)
                {
                    throw new IllegalArgumentException("Fp q value out of range");
                }
                if (Primes.hasAnySmallFactors(q) || !Primes.isMRProbablePrime(
                    q, CryptoServicesRegistrar.getSecureRandom(), getNumberOfIterations(qBitLength, certainty)))
                {
                    throw new IllegalArgumentException("Fp q value not prime");
                }

                validatedQs.add(q);
            }
        }
        else if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)
              || X509ObjectIdentifiers.id_ea_rsa.equals(algorithm)
              || PKCSObjectIdentifiers.id_RSAES_OAEP.equals(algorithm)
              || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algorithm))
        {
            RSAPublicKey params;
            try
            {
                params = RSAPublicKey.getInstance(pubInfo.parsePublicKey());
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to parse RSA key");
            }

            if ((params.getPublicExponent().intValue() & 1) == 0)
            {
                throw new IllegalArgumentException("RSA publicExponent is even");
            }

            if (!validatedMods.contains(params.getModulus()))
            {
                validate(params.getModulus());

                validatedMods.add(params.getModulus());
            }
        }
    }

    private static void validate(BigInteger modulus)
    {
        if ((modulus.intValue() & 1) == 0)
        {
            throw new IllegalArgumentException("RSA modulus is even");
        }

        // If you need to set this you need to have a serious word to whoever is sending your keys.
        if (Properties.isOverrideSet("org.bouncycastle.rsa.allow_unsafe_mod"))
        {
            return;
        }

        int maxBitLength = Properties.asInteger("org.bouncycastle.rsa.max_size", 15360);

        int modBitLength = modulus.bitLength();
        if (maxBitLength < modBitLength)
        {
            throw new IllegalArgumentException("modulus value out of range");
        }

        if (!modulus.gcd(SMALL_PRIMES_PRODUCT).equals(ONE))
        {
            throw new IllegalArgumentException("RSA modulus has a small prime factor");
        }

        int bits = modulus.bitLength() / 2;
        int iterations = bits >= 1536 ? 3
            : bits >= 1024 ? 4
            : bits >= 512 ? 7
            : 50;

        Primes.MROutput mr = Primes.enhancedMRProbablePrimeTest(modulus, CryptoServicesRegistrar.getSecureRandom(), iterations);
        if (!mr.isProvablyComposite())
        {
            throw new IllegalArgumentException("RSA modulus is not composite");
        }
    }

    private static int getNumberOfIterations(int bits, int certainty)
    {
        /*
         * NOTE: We enforce a minimum 'certainty' of 100 for bits >= 1024 (else 80). Where the
         * certainty is higher than the FIPS 186-4 tables (C.2/C.3) cater to, extra iterations
         * are added at the "worst case rate" for the excess.
         */
        if (bits >= 1536)
        {
            return certainty <= 100 ? 3
                : certainty <= 128 ? 4
                : 4 + (certainty - 128 + 1) / 2;
        }
        else if (bits >= 1024)
        {
            return certainty <= 100 ? 4
                : certainty <= 112 ? 5
                : 5 + (certainty - 112 + 1) / 2;
        }
        else if (bits >= 512)
        {
            return certainty <= 80 ? 5
                : certainty <= 100 ? 7
                : 7 + (certainty - 100 + 1) / 2;
        }
        else
        {
            return certainty <= 80 ? 40
                : 40 + (certainty - 80 + 1) / 2;
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
        return Properties.setThreadOverride(propertyName, enable);
    }

    /**
     * Remove any value for the specified override property for the current thread only.
     *
     * @param propertyName the property name for the override.
     * @return true if the override was already set true in thread local, false otherwise.
     */
    public static boolean removeThreadOverride(String propertyName)
    {
        return Properties.removeThreadOverride(propertyName);
    }

    private static class Cache
    {
        private final Map<BigInteger, Boolean> values = new WeakHashMap<BigInteger, Boolean>();
        private final BigInteger[] preserve = new BigInteger[8];

        private int preserveCounter = 0;

        public synchronized void add(BigInteger value)
        {
            values.put(value, Boolean.TRUE);
            preserve[preserveCounter] = value;
            preserveCounter = (preserveCounter + 1) % preserve.length;
        }

        public synchronized boolean contains(BigInteger value)
        {
            return values.containsKey(value);
        }

        public synchronized int size()
        {
            return values.size();
        }

        public synchronized void clear()
        {
            values.clear();
            for (int i = 0; i != preserve.length; i++)
            {
                preserve[i] = null;
            }
        }
    }

    private static class Properties
    {
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
        static boolean isOverrideSet(String propertyName)
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

        static boolean setThreadOverride(String propertyName, boolean enable)
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

        static boolean removeThreadOverride(String propertyName)
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
        static int asInteger(String propertyName, int defaultValue)
        {
            String p = getPropertyValue(propertyName);

            if (p != null)
            {
                return Integer.parseInt(p);
            }

            return defaultValue;
        }

        /**
         * Return the String value of the property propertyName. Property valuation
         * starts with java.security, then thread local, then system properties.
         *
         * @param propertyName name of property.
         * @return value of property as a String, null if not defined.
         */
        static String getPropertyValue(final String propertyName)
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
}
