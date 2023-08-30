package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.bike.BIKEKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.cmce.CMCEKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.falcon.FalconKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.hqc.HQCKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.kyber.KyberKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.lms.LMSKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.newhope.NHKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.picnic.PicnicKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;
import org.bouncycastle.util.Strings;

/**
 * To add the provider at runtime use:
 * <pre>
 * import java.security.Security;
 * import org.bouncycastle.jce.provider.BouncyCastleProvider;
 *
 * Security.addProvider(new BouncyCastleProvider());
 * </pre>
 * The provider can also be configured as part of your environment via
 * static registration by adding an entry to the java.security properties
 * file (found in $JAVA_HOME/jre/lib/security/java.security, where
 * $JAVA_HOME is the location of your JDK/JRE distribution). You'll find
 * detailed instructions in the file but basically it comes down to adding
 * a line:
 * <pre>
 * <code>
 *    security.provider.&lt;n&gt;=org.bouncycastle.jce.provider.BouncyCastleProvider
 * </code>
 * </pre>
 * Where &lt;n&gt; is the preference you want the provider at (1 being the
 * most preferred).
 * <p>Note: JCE algorithm names should be upper-case only so the case insensitive
 * test for getInstance works.
 */
public final class BouncyCastleProvider extends Provider
    implements ConfigurableProvider
{
    private static final Logger LOG = Logger.getLogger(BouncyCastleProvider.class.getName());

    private static String info = "BouncyCastle Security Provider v1.76";

    public static final String PROVIDER_NAME = "BC";

    public static final ProviderConfiguration CONFIGURATION = new BouncyCastleProviderConfiguration();

    private static final Map keyInfoConverters = new HashMap();

    private static final Class revChkClass = ClassUtil.loadClass(BouncyCastleProvider.class, "java.security.cert.PKIXRevocationChecker");

    /*
     * Configurable symmetric ciphers
     */
    private static final String SYMMETRIC_PACKAGE = "org.bouncycastle.jcajce.provider.symmetric.";

    private static final String[] SYMMETRIC_GENERIC =
    {
        "PBEPBKDF1", "PBEPBKDF2", "PBEPKCS12", "TLSKDF", "SCRYPT"
    };

    private static final String[] SYMMETRIC_MACS =
    {
        "SipHash", "SipHash128", "Poly1305"
    };

    private static final CryptoServiceProperties[] SYMMETRIC_CIPHERS =
    {
        // TODO: these numbers need a bit more work, we cap at 256 bits.
        service("AES", 256), service("ARC4", 20), service("ARIA", 256), service("Blowfish", 128), service("Camellia", 256),
        service("CAST5", 128), service("CAST6", 256), service("ChaCha", 128), service("DES", 56),  service("DESede", 112),
        service("GOST28147", 128), service("Grainv1", 128), service("Grain128", 128), service("HC128", 128), service("HC256", 256),
        service("IDEA", 128), service("Noekeon", 128), service("RC2", 128), service("RC5", 128), service("RC6", 256),
        service("Rijndael", 256), service("Salsa20", 128), service("SEED", 128), service("Serpent", 256), service("Shacal2", 128),
        service("Skipjack", 80), service("SM4", 128), service("TEA", 128), service("Twofish", 256), service("Threefish", 128),
        service("VMPC", 128), service("VMPCKSA3", 128), service("XTEA", 128), service("XSalsa20", 128), service("OpenSSLPBKDF", 128),
        service("DSTU7624", 256), service("GOST3412_2015", 256), service("Zuc", 128)
    };

     /*
     * Configurable asymmetric ciphers
     */
    private static final String ASYMMETRIC_PACKAGE = "org.bouncycastle.jcajce.provider.asymmetric.";

    // this one is required for GNU class path - it needs to be loaded first as the
    // later ones configure it.
    private static final String[] ASYMMETRIC_GENERIC =
    {
        "X509", "IES", "COMPOSITE", "EXTERNAL"
    };

    private static final String[] ASYMMETRIC_CIPHERS =
    {
        "DSA", "DH", "EC", "RSA", "GOST", "ECGOST", "ElGamal", "DSTU4145", "GM", "EdEC", "LMS", "SPHINCSPlus", "Dilithium", "Falcon", "NTRU"
    };

    /*
     * Configurable digests
     */
    private static final String DIGEST_PACKAGE = "org.bouncycastle.jcajce.provider.digest.";
    private static final String[] DIGESTS =
    {
        "GOST3411", "Keccak", "MD2", "MD4", "MD5", "SHA1", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320", "SHA224",
        "SHA256", "SHA384", "SHA512", "SHA3", "Skein", "SM3", "Tiger", "Whirlpool", "Blake2b", "Blake2s", "DSTU7564",
        "Haraka", "Blake3"
    };

    /*
     * Configurable keystores
     */
    private static final String KEYSTORE_PACKAGE = "org.bouncycastle.jcajce.provider.keystore.";
    private static final String[] KEYSTORES =
    {
        "BC", "BCFKS", "PKCS12"
    };

    /*
     * Configurable secure random
     */
    private static final String SECURE_RANDOM_PACKAGE = "org.bouncycastle.jcajce.provider.drbg.";
    private static final String[] SECURE_RANDOMS =
    {
        "DRBG"
    };

    private Map<String, Service> serviceMap = new ConcurrentHashMap<String, Service>();

    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public BouncyCastleProvider()
    {
        super(PROVIDER_NAME, 1.76, info);

        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        loadAlgorithms(DIGEST_PACKAGE, DIGESTS);

        loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_GENERIC);

        loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_MACS);

        loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_CIPHERS);

        loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_GENERIC);

        loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_CIPHERS);

        loadAlgorithms(KEYSTORE_PACKAGE, KEYSTORES);

        loadAlgorithms(SECURE_RANDOM_PACKAGE, SECURE_RANDOMS);

        loadPQCKeys();  // so we can handle certificates containing them.

        //
        // X509Store
        //
        put("X509Store.CERTIFICATE/COLLECTION", "org.bouncycastle.jce.provider.X509StoreCertCollection");
        put("X509Store.ATTRIBUTECERTIFICATE/COLLECTION", "org.bouncycastle.jce.provider.X509StoreAttrCertCollection");
        put("X509Store.CRL/COLLECTION", "org.bouncycastle.jce.provider.X509StoreCRLCollection");
        put("X509Store.CERTIFICATEPAIR/COLLECTION", "org.bouncycastle.jce.provider.X509StoreCertPairCollection");

        put("X509Store.CERTIFICATE/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPCerts");
        put("X509Store.CRL/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPCRLs");
        put("X509Store.ATTRIBUTECERTIFICATE/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPAttrCerts");
        put("X509Store.CERTIFICATEPAIR/LDAP", "org.bouncycastle.jce.provider.X509StoreLDAPCertPairs");

        //
        // X509StreamParser
        //
        put("X509StreamParser.CERTIFICATE", "org.bouncycastle.jce.provider.X509CertParser");
        put("X509StreamParser.ATTRIBUTECERTIFICATE", "org.bouncycastle.jce.provider.X509AttrCertParser");
        put("X509StreamParser.CRL", "org.bouncycastle.jce.provider.X509CRLParser");
        put("X509StreamParser.CERTIFICATEPAIR", "org.bouncycastle.jce.provider.X509CertPairParser");

        //
        // cipher engines
        //
        put("Cipher.BROKENPBEWITHMD5ANDDES", "org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithMD5AndDES");

        put("Cipher.BROKENPBEWITHSHA1ANDDES", "org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES");


        put("Cipher.OLDPBEWITHSHAANDTWOFISH-CBC", "org.bouncycastle.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish");

        // Certification Path API
        if (revChkClass != null)
        {
            put("CertPathValidator.RFC3281", "org.bouncycastle.jce.provider.PKIXAttrCertPathValidatorSpi");
            put("CertPathBuilder.RFC3281", "org.bouncycastle.jce.provider.PKIXAttrCertPathBuilderSpi");
            put("CertPathValidator.RFC3280", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi_8");
            put("CertPathBuilder.RFC3280", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi_8");
            put("CertPathValidator.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi_8");
            put("CertPathBuilder.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi_8");
        }
        else
        {
            put("CertPathValidator.RFC3281", "org.bouncycastle.jce.provider.PKIXAttrCertPathValidatorSpi");
            put("CertPathBuilder.RFC3281", "org.bouncycastle.jce.provider.PKIXAttrCertPathBuilderSpi");
            put("CertPathValidator.RFC3280", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi");
            put("CertPathBuilder.RFC3280", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi");
            put("CertPathValidator.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathValidatorSpi");
            put("CertPathBuilder.PKIX", "org.bouncycastle.jce.provider.PKIXCertPathBuilderSpi");
        }
        put("CertStore.Collection", "org.bouncycastle.jce.provider.CertStoreCollectionSpi");
        put("CertStore.LDAP", "org.bouncycastle.jce.provider.X509LDAPCertStoreSpi");
        put("CertStore.Multi", "org.bouncycastle.jce.provider.MultiCertStoreSpi");
        put("Alg.Alias.CertStore.X509LDAP", "LDAP");

        getService("SecureRandom", "DEFAULT");  // prime for new SecureRandom() on 1.8 JVMs.
    }

    public final Service getService(final String type, final String algorithm)
    {
        String upperCaseAlgName = Strings.toUpperCase(algorithm);
        final String key = type + "." + upperCaseAlgName;

        Service service = serviceMap.get(key);

        if (service == null)
        {
            synchronized (this)
            {
                if (!serviceMap.containsKey(key))
                {
                    service = AccessController.doPrivileged(new PrivilegedAction<Service>()
                    {
                        @Override
                        public Service run()
                        {
                            Service service = BouncyCastleProvider.super.getService(type, algorithm);
                            if (service == null)
                            {
                                return null;
                            }
                            serviceMap.put(key, service);
                            // remove legacy entry and swap to service entry
                            BouncyCastleProvider.super.remove(service.getType() + "." + service.getAlgorithm());
                            BouncyCastleProvider.super.putService(service);

                            return service;
                        }
                    });
                }
                else
                {
                    service = serviceMap.get(key);
                }
            }
        }

        return service;
    }

    private void loadAlgorithms(String packageName, String[] names)
    {
        for (int i = 0; i != names.length; i++)
        {
            loadServiceClass(packageName, names[i]);
        }
    }

    private void loadAlgorithms(String packageName, CryptoServiceProperties[] services)
    {
        for (int i = 0; i != services.length; i++)
        {
            CryptoServiceProperties service = services[i];
            try
            {
                CryptoServicesRegistrar.checkConstraints(service);

                loadServiceClass(packageName, service.getServiceName());
            }
            catch (CryptoServiceConstraintsException e)
            {
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("service for " + service.getServiceName() + " ignored due to constraints");
                }
            }
        }
    }

    private void loadServiceClass(String packageName, String serviceName)
    {
        Class clazz = ClassUtil.loadClass(BouncyCastleProvider.class, packageName + serviceName + "$Mappings");

        if (clazz != null)
        {
            try
            {
                ((AlgorithmProvider)clazz.newInstance()).configure(this);
            }
            catch (Exception e)
            {   // this should never ever happen!!
                throw new InternalError("cannot create instance of "
                    + packageName + serviceName + "$Mappings : " + e);
            }
        }
    }

    private void loadPQCKeys()
    {
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, new SPHINCSPlusKeyFactorySpi());

        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_128s, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_192s, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_sha2_256s, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(new ASN1ObjectIdentifier("1.3.9999.6.4.10"), new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_128f, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_192f, new SPHINCSPlusKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.sphincsPlus_shake_256f, new SPHINCSPlusKeyFactorySpi());

        addKeyInfoConverter(PQCObjectIdentifiers.sphincs256, new Sphincs256KeyFactorySpi());
        addKeyInfoConverter(PQCObjectIdentifiers.newHope, new NHKeyFactorySpi());
        addKeyInfoConverter(PQCObjectIdentifiers.xmss, new XMSSKeyFactorySpi());
        addKeyInfoConverter(IsaraObjectIdentifiers.id_alg_xmss, new XMSSKeyFactorySpi());
        addKeyInfoConverter(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyFactorySpi());
        addKeyInfoConverter(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTKeyFactorySpi());
        addKeyInfoConverter(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.picnic_key, new PicnicKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.falcon_512, new FalconKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.falcon_1024, new FalconKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.dilithium2, new DilithiumKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.dilithium3, new DilithiumKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.dilithium5, new DilithiumKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.dilithium2_aes, new DilithiumKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.dilithium3_aes, new DilithiumKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.dilithium5_aes, new DilithiumKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber512, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber768, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber1024, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.mceliece348864_r3, new CMCEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.mceliece460896_r3, new CMCEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.mceliece6688128_r3, new CMCEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.mceliece6960119_r3, new CMCEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.mceliece8192128_r3, new CMCEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.bike128, new BIKEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.bike192, new BIKEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.bike256, new BIKEKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.hqc128, new HQCKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.hqc192, new HQCKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.hqc256, new HQCKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber1024, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber512_aes, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber768_aes, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.kyber1024_aes, new KyberKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.ntruhps2048509, new NTRUKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.ntruhps2048677, new NTRUKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.ntruhps4096821, new NTRUKeyFactorySpi());
        addKeyInfoConverter(BCObjectIdentifiers.ntruhrss701, new NTRUKeyFactorySpi());
    }

    public void setParameter(String parameterName, Object parameter)
    {
        synchronized (CONFIGURATION)
        {
            ((BouncyCastleProviderConfiguration)CONFIGURATION).setParameter(parameterName, parameter);
        }
    }

    public boolean hasAlgorithm(String type, String name)
    {
        return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
    }

    public void addAlgorithm(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addAlgorithm(String key, String value, Map<String, String> attributes)
    {
        addAlgorithm(key, value);
        addAttributes(key, attributes);
    }

    public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className)
    {
        addAlgorithm(type + "." + oid, className);
        addAlgorithm(type + ".OID." + oid, className);
    }

    public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className, Map<String, String> attributes)
    {
        addAlgorithm(type, oid, className);
        addAttributes(type + "." + oid, attributes);
        addAttributes(type + ".OID." + oid, attributes);
    }
    
    public void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter)
    {
        synchronized (keyInfoConverters)
        {
            keyInfoConverters.put(oid, keyInfoConverter);
        }
    }

    public AsymmetricKeyInfoConverter getKeyInfoConverter(ASN1ObjectIdentifier oid)
    {
        return (AsymmetricKeyInfoConverter)keyInfoConverters.get(oid);
    }

    public void addAttributes(String key, Map<String, String> attributeMap)
    {
        put(key + " ImplementedIn", "Software");

        for (Iterator it = attributeMap.keySet().iterator(); it.hasNext();)
        {
            String attributeName = (String)it.next();
            String attributeKey = key + " " + attributeName;
            if (containsKey(attributeKey))
            {
                throw new IllegalStateException("duplicate provider attribute key (" + attributeKey + ") found");
            }

            put(attributeKey, attributeMap.get(attributeName));
        }
    }

    private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(ASN1ObjectIdentifier algorithm)
    {
        synchronized (keyInfoConverters)
        {
            return (AsymmetricKeyInfoConverter)keyInfoConverters.get(algorithm);
        }
    }

    public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        if (publicKeyInfo.getAlgorithm().getAlgorithm().on(BCObjectIdentifiers.picnic_key))
        {
            return new PicnicKeyFactorySpi().generatePublic(publicKeyInfo);
        }
        
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(publicKeyInfo.getAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePublic(publicKeyInfo);
    }

    public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
        throws IOException
    {
        AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatePrivate(privateKeyInfo);
    }

    private static CryptoServiceProperties service(String name, int bitsOfSecurity)
    {
        return new JcaCryptoService(name, bitsOfSecurity);
    }

    private static class JcaCryptoService
        implements CryptoServiceProperties
    {

        private final String name;
        private final int bitsOfSecurity;

        JcaCryptoService(String name, int bitsOfSecurity)
        {
            this.name = name;
            this.bitsOfSecurity = bitsOfSecurity;
        }

        public int bitsOfSecurity()
        {
            return bitsOfSecurity;
        }

        public String getServiceName()
        {
            return name;
        }

        public CryptoServicePurpose getPurpose()
        {
            return CryptoServicePurpose.ANY;
        }

        public Object getParams()
        {
            return null;
        }
    }
}
