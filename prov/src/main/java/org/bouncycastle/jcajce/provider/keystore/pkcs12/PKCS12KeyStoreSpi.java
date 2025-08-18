package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.provider.keystore.util.ParameterUtil;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.BCKeyStore;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKPKCS12StoreParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PKCS12KeyStoreSpi
    extends KeyStoreSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore
{
    static final String PKCS12_MAX_IT_COUNT_PROPERTY = "org.bouncycastle.pkcs12.max_it_count";

    private final JcaJceHelper helper = new BCJcaJceHelper();

    private static final int SALT_SIZE = 20;
    private static final int MIN_ITERATIONS = 50 * 1024;

    private static final DefaultSecretKeyProvider keySizeProvider = new DefaultSecretKeyProvider();

    private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
    private IgnoresCaseHashtable localIds = new IgnoresCaseHashtable();
    private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
    private Hashtable chainCerts = new Hashtable();
    private Hashtable keyCerts = new Hashtable();



    //
    // generic object types
    //
    static final int NULL = 0;
    static final int CERTIFICATE = 1;
    static final int KEY = 2;
    static final int SECRET = 3;
    static final int SEALED = 4;

    //
    // key types
    //
    static final int KEY_PRIVATE = 0;
    static final int KEY_PUBLIC = 1;
    static final int KEY_SECRET = 2;

    protected SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

    // use of final causes problems with JDK 1.2 compiler
    private CertificateFactory certFact;
    private ASN1ObjectIdentifier keyAlgorithm;
    private ASN1ObjectIdentifier certAlgorithm;

    private AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
    private int itCount = 2 * MIN_ITERATIONS;
    private int saltLength = 20;

    private class CertId
    {
        byte[] id;

        CertId(
            PublicKey key)
        {
            this.id = createSubjectKeyId(key).getKeyIdentifier();
        }

        CertId(
            byte[] id)
        {
            this.id = id;
        }

        public int hashCode()
        {
            return Arrays.hashCode(id);
        }

        public boolean equals(
            Object o)
        {
            if (o == this)
            {
                return true;
            }

            if (!(o instanceof CertId))
            {
                return false;
            }

            CertId cId = (CertId)o;

            return Arrays.areEqual(id, cId.id);
        }
    }

    private static boolean isPBKDF2(ASN1ObjectIdentifier oid)
    {
        return oid.equals(NISTObjectIdentifiers.id_aes256_CBC)
            || oid.equals(NISTObjectIdentifiers.id_aes256_GCM)
            || oid.equals(NISTObjectIdentifiers.id_aes128_CBC)
            || oid.equals(NISTObjectIdentifiers.id_aes128_GCM);
    }

    private static int getKeyLength(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_aes256_CBC) || oid.equals(NISTObjectIdentifiers.id_aes256_GCM))
        {
            return 32;
        }
        else
        {
            return 16;
        }
    }

    public PKCS12KeyStoreSpi(
        JcaJceHelper helper,
        ASN1ObjectIdentifier keyAlgorithm,
        ASN1ObjectIdentifier certAlgorithm)
    {
        this.keyAlgorithm = keyAlgorithm;
        this.certAlgorithm = certAlgorithm;

        try
        {
            certFact = helper.createCertificateFactory("X.509");
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException("can't create cert factory - " + e.toString());
        }
    }

    private SubjectKeyIdentifier createSubjectKeyId(
        PublicKey pubKey)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

            return new SubjectKeyIdentifier(getDigest(info));
        }
        catch (Exception e)
        {
            throw new RuntimeException("error creating key");
        }
    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki)
    {
        Digest digest = DigestFactory.createSHA1();
        byte[] resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }

    public void setRandom(
        SecureRandom rand)
    {
        this.random = rand;
    }

    public boolean engineProbe(InputStream stream)
        throws IOException
    {
        return false;
    }

    public Enumeration engineAliases()
    {
        Hashtable tab = new Hashtable();

        Enumeration e = certs.keys();
        while (e.hasMoreElements())
        {
            tab.put(e.nextElement(), "cert");
        }

        e = keys.keys();
        while (e.hasMoreElements())
        {
            String a = (String)e.nextElement();
            if (tab.get(a) == null)
            {
                tab.put(a, "key");
            }
        }

        return tab.keys();
    }

    public boolean engineContainsAlias(
        String alias)
    {
        return (certs.get(alias) != null || keys.get(alias) != null);
    }

    /**
     * this is not quite complete - we should follow up on the chain, a bit
     * tricky if a certificate appears in more than one chain... the store method
     * now prunes out unused certificates from the chain map if they are present.
     */
    public void engineDeleteEntry(
        String alias)
        throws KeyStoreException
    {
        Certificate cert = (Certificate)certs.remove(alias);
        if (cert != null)
        {
            chainCerts.remove(new CertId(cert.getPublicKey()));
        }

        Key key = (Key)keys.remove(alias);
        if (key != null)
        {
            String id = (String)localIds.remove(alias);
            if (id != null)
            {
                Certificate keyCert = (Certificate)keyCerts.remove(id);
                if (keyCert != null)
                {
                    chainCerts.remove(new CertId(keyCert.getPublicKey()));
                }
            }
        }
    }

    /**
     * simply return the cert for the private key
     */
    public Certificate engineGetCertificate(
        String alias)
    {
        if (alias == null)
        {
            throw new IllegalArgumentException("null alias passed to getCertificate.");
        }

        Certificate c = (Certificate)certs.get(alias);

        //
        // look up the key table - and try the local key id
        //
        if (c == null)
        {
            String id = (String)localIds.get(alias);
            if (id != null)
            {
                c = (Certificate)keyCerts.get(id);
            }
            else
            {
                c = (Certificate)keyCerts.get(alias);
            }
        }

        return c;
    }

    public String engineGetCertificateAlias(
        Certificate cert)
    {
        Enumeration c = certs.elements();
        Enumeration k = certs.keys();

        while (c.hasMoreElements())
        {
            Certificate tc = (Certificate)c.nextElement();
            String ta = (String)k.nextElement();

            if (tc.equals(cert))
            {
                return ta;
            }
        }

        c = keyCerts.elements();
        k = keyCerts.keys();

        while (c.hasMoreElements())
        {
            Certificate tc = (Certificate)c.nextElement();
            String ta = (String)k.nextElement();

            if (tc.equals(cert))
            {
                return ta;
            }
        }

        return null;
    }

    public Certificate[] engineGetCertificateChain(
        String alias)
    {
        if (alias == null)
        {
            throw new IllegalArgumentException("null alias passed to getCertificateChain.");
        }

        if (!engineIsKeyEntry(alias))
        {
            return null;
        }

        Certificate c = engineGetCertificate(alias);

        if (c != null)
        {
            Vector cs = new Vector();

            while (c != null)
            {
                X509Certificate x509c = (X509Certificate)c;
                Certificate nextC = null;

                byte[] akiExtValue = x509c.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                if (akiExtValue != null)
                {
                    AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(
                        ASN1OctetString.getInstance(akiExtValue).getOctets());

                    byte[] keyID = aki.getKeyIdentifierOctets();
                    if (null != keyID)
                    {
                        nextC = (Certificate)chainCerts.get(new CertId(keyID));
                    }
                }

                if (nextC == null)
                {
                    //
                    // no authority key id, try the Issuer DN
                    //
                    Principal i = x509c.getIssuerDN();
                    Principal s = x509c.getSubjectDN();

                    if (!i.equals(s))
                    {
                        Enumeration e = chainCerts.keys();

                        while (e.hasMoreElements())
                        {
                            X509Certificate crt = (X509Certificate)chainCerts.get(e.nextElement());
                            Principal sub = crt.getSubjectDN();
                            if (sub.equals(i))
                            {
                                try
                                {
                                    x509c.verify(crt.getPublicKey());
                                    nextC = crt;
                                    break;
                                }
                                catch (Exception ex)
                                {
                                    // continue
                                }
                            }
                        }
                    }
                }

                if (cs.contains(c))
                {
                    c = null;          // we've got a certificate chain loop time to stop
                }
                else
                {
                    cs.addElement(c);
                    if (nextC != c)     // self signed - end of the chain
                    {
                        c = nextC;
                    }
                    else
                    {
                        c = null;
                    }
                }
            }

            Certificate[] certChain = new Certificate[cs.size()];

            for (int i = 0; i != certChain.length; i++)
            {
                certChain[i] = (Certificate)cs.elementAt(i);
            }

            return certChain;
        }

        return null;
    }

    public Date engineGetCreationDate(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias == null");
        }
        if (keys.get(alias) == null && certs.get(alias) == null)
        {
            return null;
        }
        return new Date();
    }

    public Key engineGetKey(
        String alias,
        char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if (alias == null)
        {
            throw new IllegalArgumentException("null alias passed to getKey.");
        }

        return (Key)keys.get(alias);
    }

    public boolean engineIsCertificateEntry(
        String alias)
    {
        return (certs.get(alias) != null && keys.get(alias) == null);
    }

    public boolean engineIsKeyEntry(
        String alias)
    {
        return (keys.get(alias) != null);
    }

    public void engineSetCertificateEntry(
        String alias,
        Certificate cert)
        throws KeyStoreException
    {
        if (keys.get(alias) != null)
        {
            throw new KeyStoreException("There is a key entry with the name " + alias + ".");
        }

        certs.put(alias, cert);
        chainCerts.put(new CertId(cert.getPublicKey()), cert);
    }

    public void engineSetKeyEntry(
        String alias,
        byte[] key,
        Certificate[] chain)
        throws KeyStoreException
    {
        throw new RuntimeException("operation not supported");
    }

    public void engineSetKeyEntry(
        String alias,
        Key key,
        char[] password,
        Certificate[] chain)
        throws KeyStoreException
    {
        if (!(key instanceof PrivateKey))
        {
            throw new KeyStoreException("PKCS12 does not support non-PrivateKeys");
        }

        if ((key instanceof PrivateKey) && (chain == null))
        {
            throw new KeyStoreException("no certificate chain for private key");
        }

        if (keys.get(alias) != null)
        {
            engineDeleteEntry(alias);
        }

        keys.put(alias, key);
        if (chain != null)
        {
            certs.put(alias, chain[0]);

            for (int i = 0; i != chain.length; i++)
            {
                chainCerts.put(new CertId(chain[i].getPublicKey()), chain[i]);
            }
        }
    }

    public int engineSize()
    {
        Hashtable tab = new Hashtable();

        Enumeration e = certs.keys();
        while (e.hasMoreElements())
        {
            tab.put(e.nextElement(), "cert");
        }

        e = keys.keys();
        while (e.hasMoreElements())
        {
            String a = (String)e.nextElement();
            if (tab.get(a) == null)
            {
                tab.put(a, "key");
            }
        }

        return tab.size();
    }

    protected PrivateKey unwrapKey(
        AlgorithmIdentifier algId,
        byte[] data,
        char[] password,
        boolean wrongPKCS12Zero)
        throws IOException
    {
        ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
        try
        {
            if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
            {
                PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
                PBEParameterSpec defParams = new PBEParameterSpec(
                    pbeParams.getIV(),
                    validateIterationCount(pbeParams.getIterations()));

                Cipher cipher = helper.createCipher(algorithm.getId());

                PKCS12Key key = new PKCS12Key(password, wrongPKCS12Zero);

                cipher.init(Cipher.UNWRAP_MODE, key, defParams);

                // we pass "" as the key algorithm type as it is unknown at this point
                return (PrivateKey)cipher.unwrap(data, "", Cipher.PRIVATE_KEY);
            }
            else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
            {

                Cipher cipher = createCipher(Cipher.UNWRAP_MODE, password, algId);

                // we pass "" as the key algorithm type as it is unknown at this point
                return (PrivateKey)cipher.unwrap(data, "", Cipher.PRIVATE_KEY);
            }
        }
        catch (Exception e)
        {
            throw new IOException("exception unwrapping private key - " + e.toString());
        }

        throw new IOException("exception unwrapping private key - cannot recognise: " + algorithm);
    }

    protected byte[] wrapKey(
        String algorithm,
        Key key,
        PKCS12PBEParams pbeParams,
        char[] password)
        throws IOException
    {
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        byte[] out;

        try
        {
            SecretKeyFactory keyFact = helper.createSecretKeyFactory(algorithm);
            PBEParameterSpec defParams = new PBEParameterSpec(
                pbeParams.getIV(),
                BigIntegers.intValueExact(pbeParams.getIterations()));

            Cipher cipher = helper.createCipher(algorithm);

            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), defParams);

            out = cipher.wrap(key);
        }
        catch (Exception e)
        {
            throw new IOException("exception encrypting data - " + e.toString());
        }

        return out;
    }

    protected byte[] wrapKey(
        EncryptionScheme encAlgId,
        Key key,
        PBKDF2Params pbeParams,
        char[] password)
        throws IOException
    {
        PBEKeySpec pbeSpec = new PBEKeySpec(password, pbeParams.getSalt(),
            BigIntegers.intValueExact(pbeParams.getIterationCount()),
            BigIntegers.intValueExact(pbeParams.getKeyLength()) * 8);
        byte[] out;

        try
        {
            SecretKeyFactory keyFact = helper.createSecretKeyFactory("PBKDF2withHMacSHA256");

            Cipher cipher = helper.createCipher(encAlgId.getAlgorithm().getId());

            AlgorithmParameters algParams = AlgorithmParameters.getInstance(encAlgId.getAlgorithm().getId());
            algParams.init(encAlgId.getParameters().toASN1Primitive().getEncoded());

            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), algParams);

            out = cipher.wrap(key);
        }
        catch (Exception e)
        {
            throw new IOException("exception encrypting data - " + e.toString());
        }

        return out;
    }

    protected byte[] cryptData(
        boolean forEncryption,
        AlgorithmIdentifier algId,
        char[] password,
        boolean wrongPKCS12Zero,
        byte[] data)
        throws IOException
    {
        ASN1ObjectIdentifier algorithm = algId.getAlgorithm();
        int mode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

        if (algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds))
        {
            PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algId.getParameters());
            PKCS12Key key = new PKCS12Key(password, wrongPKCS12Zero);

            try
            {
                PBEParameterSpec defParams = new PBEParameterSpec(
                    pbeParams.getIV(),
                    BigIntegers.intValueExact(pbeParams.getIterations()));

                Cipher cipher = helper.createCipher(algorithm.getId());

                cipher.init(mode, key, defParams);
                return cipher.doFinal(data);
            }
            catch (Exception e)
            {
                throw new IOException("exception decrypting data - " + e.toString());
            }
            finally
            {
                Arrays.clear(key.getPassword());
            }
        }
        else if (algorithm.equals(PKCSObjectIdentifiers.id_PBES2))
        {
            try
            {
                Cipher cipher = createCipher(mode, password, algId);

                return cipher.doFinal(data);
            }
            catch (Exception e)
            {
                throw new IOException("exception decrypting data - " + e.toString());
            }
        }
        else
        {
            throw new IOException("unknown PBE algorithm: " + algorithm);
        }
    }

    private Cipher createCipher(int mode, char[] password, AlgorithmIdentifier algId)
        throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException
    {
        PBES2Parameters alg = PBES2Parameters.getInstance(algId.getParameters());
        PBKDF2Params func = PBKDF2Params.getInstance(alg.getKeyDerivationFunc().getParameters());
        AlgorithmIdentifier encScheme = AlgorithmIdentifier.getInstance(alg.getEncryptionScheme());

        SecretKeyFactory keyFact = helper.createSecretKeyFactory(alg.getKeyDerivationFunc().getAlgorithm().getId());
        SecretKey key;

        if (func.isDefaultPrf())
        {
            key = keyFact.generateSecret(new PBEKeySpec(password, func.getSalt(), validateIterationCount(func.getIterationCount()), keySizeProvider.getKeySize(encScheme)));
        }
        else
        {
            key = keyFact.generateSecret(new PBKDF2KeySpec(password, func.getSalt(), validateIterationCount(func.getIterationCount()), keySizeProvider.getKeySize(encScheme), func.getPrf()));
        }

        Cipher cipher = helper.createCipher(alg.getEncryptionScheme().getAlgorithm().getId());
        ASN1Encodable encParams = alg.getEncryptionScheme().getParameters();
        if (encParams instanceof ASN1OctetString)
        {
            cipher.init(mode, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
        }
        else
        {
            ASN1Sequence params = ASN1Sequence.getInstance(encParams);

            if (params.getObjectAt(1) instanceof ASN1ObjectIdentifier)
            {
                // TODO: at the moment it's just GOST, but...
                GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                cipher.init(mode, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
            }
            else
            {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance(encScheme.getAlgorithm().getId(), "BC");

                try
                {
                    algParams.init(params.getEncoded());
                }
                catch (IOException e)
                {
                    throw new InvalidKeySpecException(e.getMessage());
                }

                cipher.init(mode, key, algParams);
            }
        }
        return cipher;
    }

    public void engineLoad(KeyStore.LoadStoreParameter loadStoreParameter)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        if (loadStoreParameter == null)
        {
            engineLoad(null, null);
        }
        else if (loadStoreParameter instanceof BCLoadStoreParameter)
        {
            BCLoadStoreParameter bcParam = (BCLoadStoreParameter)loadStoreParameter;

            engineLoad(bcParam.getInputStream(), ParameterUtil.extractPassword(loadStoreParameter));
        }
        else
        {
            throw new IllegalArgumentException(
                "no support for 'param' of type " + loadStoreParameter.getClass().getName());
        }
    }

    public void engineLoad(
        InputStream stream,
        char[] password)
        throws IOException
    {
        if (stream == null)     // just initialising
        {
            return;
        }

        boolean noMac = true;
        boolean noEnc = true;

        BufferedInputStream bufIn = new BufferedInputStream(stream);

        bufIn.mark(10);

        int head = bufIn.read();
        if (head < 0)
        {
            throw new EOFException("no data in keystore stream");
        }
        if (head != 0x30)
        {
            throw new IOException("stream does not represent a PKCS12 key store");
        }

        bufIn.reset();

        ASN1InputStream bIn = new ASN1InputStream(bufIn);

        Pfx bag;
        try
        {
            bag = Pfx.getInstance(bIn.readObject());
        }
        catch (Exception e)
        {
            throw new IOException(e.getMessage());
        }

        ContentInfo info = bag.getAuthSafe();
        Vector chain = new Vector();
        boolean unmarkedKey = false;
        boolean wrongPKCS12Zero = false;

        if (bag.getMacData() != null)           // check the mac code
        {
            if (password == null)
            {
                throw new NullPointerException("no password supplied when one expected");
            }

            noMac = false;
            MacData mData = bag.getMacData();
            DigestInfo dInfo = mData.getMac();
            macAlgorithm = dInfo.getAlgorithmId();
            byte[] salt = mData.getSalt();
            itCount = validateIterationCount(mData.getIterationCount());
            saltLength = salt.length;

            byte[] data = ((ASN1OctetString)info.getContent()).getOctets();

            try
            {
                byte[] res = calculatePbeMac(macAlgorithm.getAlgorithm(), salt, itCount, password, false, data);
                byte[] dig = dInfo.getDigest();

                if (!Arrays.constantTimeAreEqual(res, dig))
                {
                    if (password.length > 0)
                    {
                        throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                    }

                    // Try with incorrect zero length password
                    res = calculatePbeMac(macAlgorithm.getAlgorithm(), salt, itCount, password, true, data);

                    if (!Arrays.constantTimeAreEqual(res, dig))
                    {
                        throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
                    }

                    wrongPKCS12Zero = true;
                }
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new IOException("error constructing MAC: " + e.toString());
            }
        }

        keys = new IgnoresCaseHashtable();
        localIds = new IgnoresCaseHashtable();

        if (info.getContentType().equals(data))
        {
            ASN1OctetString content = ASN1OctetString.getInstance(info.getContent());
            AuthenticatedSafe authSafe = AuthenticatedSafe.getInstance(content.getOctets());
            ContentInfo[] c = authSafe.getContentInfo();

            for (int i = 0; i != c.length; i++)
            {
                if (c[i].getContentType().equals(data))
                {
                    ASN1OctetString authSafeContent = ASN1OctetString.getInstance(c[i].getContent());
                    ASN1Sequence seq = ASN1Sequence.getInstance(authSafeContent.getOctets());

                    for (int j = 0; j != seq.size(); j++)
                    {
                        SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));
                        if (b.getBagId().equals(pkcs8ShroudedKeyBag))
                        {
                            unmarkedKey = processShroudedKeyBag(b, password, wrongPKCS12Zero);
                            noEnc = false;
                        }
                        else if (b.getBagId().equals(certBag))
                        {
                            chain.addElement(b);
                        }
                        else if (b.getBagId().equals(keyBag))
                        {
                            processKeyBag(b);
                        }
                        else
                        {
                            // -DM 2 System.out.println
                            System.out.println("extra in data " + b.getBagId());
                            System.out.println(ASN1Dump.dumpAsString(b));
                        }
                    }
                }
                else if (c[i].getContentType().equals(encryptedData))
                {
                    EncryptedData d = EncryptedData.getInstance(c[i].getContent());
                    byte[] octets = cryptData(false, d.getEncryptionAlgorithm(),
                        password, wrongPKCS12Zero, d.getContent().getOctets());
                    ASN1Sequence seq = ASN1Sequence.getInstance(octets);

                    noEnc = false;
                    for (int j = 0; j != seq.size(); j++)
                    {
                        SafeBag b = SafeBag.getInstance(seq.getObjectAt(j));
                        if (b.getBagId().equals(certBag))
                        {
                            chain.addElement(b);
                        }
                        else if (b.getBagId().equals(pkcs8ShroudedKeyBag))
                        {
                            unmarkedKey = processShroudedKeyBag(b, password, wrongPKCS12Zero);
                        }
                        else if (b.getBagId().equals(keyBag))
                        {
                            processKeyBag(b);
                        }
                        else
                        {
                            // -DM 2 System.out.println
                            System.out.println("extra in encryptedData " + b.getBagId());
                            System.out.println(ASN1Dump.dumpAsString(b));
                        }
                    }
                }
                else
                {
                    // -DM 2 System.out.println
                    System.out.println("extra " + c[i].getContentType().getId());
                    System.out.println("extra " + ASN1Dump.dumpAsString(c[i].getContent()));
                }
            }
        }

        certs = new IgnoresCaseHashtable();
        chainCerts = new Hashtable();
        keyCerts = new Hashtable();

        for (int i = 0; i != chain.size(); i++)
        {
            SafeBag b = (SafeBag)chain.elementAt(i);
            CertBag cb = CertBag.getInstance(b.getBagValue());

            if (!cb.getCertId().equals(x509Certificate))
            {
                throw new RuntimeException("Unsupported certificate type: " + cb.getCertId());
            }

            Certificate cert;

            try
            {
                ByteArrayInputStream cIn = new ByteArrayInputStream(
                    ((ASN1OctetString)cb.getCertValue()).getOctets());
                cert = certFact.generateCertificate(cIn);
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.toString());
            }

            //
            // set the attributes
            //
            ASN1OctetString localId = null;
            String alias = null;

            if (b.getBagAttributes() != null)
            {
                Enumeration e = b.getBagAttributes().getObjects();
                while (e.hasMoreElements())
                {
                    ASN1Sequence sq = ASN1Sequence.getInstance(e.nextElement());
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sq.getObjectAt(0));
                    ASN1Set attrSet = ASN1Set.getInstance(sq.getObjectAt(1));

                    if (attrSet.size() > 0)   // sometimes this is empty!
                    {
                        ASN1Primitive attr = (ASN1Primitive)attrSet.getObjectAt(0);
                        PKCS12BagAttributeCarrier bagAttr = null;

                        if (cert instanceof PKCS12BagAttributeCarrier)
                        {
                            bagAttr = (PKCS12BagAttributeCarrier)cert;

                            ASN1Encodable existing = bagAttr.getBagAttribute(oid);
                            if (existing != null)
                            {
                                // we've found more than one - one might be incorrect
                                if (oid.equals(pkcs_9_at_localKeyId))
                                {
                                    // -DM Hex.toHexString
                                    String id = Hex.toHexString(((ASN1OctetString)attr).getOctets());
                                    if (!(keys.keys.containsKey(id) || localIds.keys.containsKey(id)))
                                    {
                                        continue; // ignore this one - it's not valid
                                    }
                                }

                                // OK, but the value has to be the same
                                if (!existing.toASN1Primitive().equals(attr))
                                {
                                    throw new IOException(
                                        "attempt to add existing attribute with different value");
                                }
                            }
                            else
                            {
                                if (attrSet.size() > 1)
                                {
                                    bagAttr.setBagAttribute(oid, attrSet);
                                }
                                else
                                {
                                    bagAttr.setBagAttribute(oid, attr);
                                }
                            }
                        }

                        if (oid.equals(pkcs_9_at_friendlyName))
                        {
                            alias = ((ASN1BMPString)attr).getString();
                        }
                        else if (oid.equals(pkcs_9_at_localKeyId))
                        {
                            localId = (ASN1OctetString)attr;
                        }
                    }
                }
            }

            chainCerts.put(new CertId(cert.getPublicKey()), cert);

            if (unmarkedKey)
            {
                if (keyCerts.isEmpty())
                {
                    String name = new String(Hex.encode(createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier()));

                    keyCerts.put(name, cert);
                    keys.put(name, keys.remove("unmarked"));
                }
            }
            else
            {
                //
                // the local key id needs to override the friendly name
                //
                if (localId != null)
                {
                    String name = new String(Hex.encode(localId.getOctets()));

                    keyCerts.put(name, cert);
                }
                if (alias != null)
                {
                    certs.put(alias, cert);
                }
            }
        }

        if (noMac && noEnc)
        {
            if (password != null && password.length != 0)
            {
                if (!Properties.isOverrideSet("org.bouncycastle.pkcs12.ignore_useless_passwd"))
                {
                    throw new IOException("password supplied for keystore that does not require one");
                }
            }
        }
    }

    private boolean processShroudedKeyBag(SafeBag b, char[] password, boolean wrongPKCS12Zero)
        throws IOException
    {
        org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo eIn = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getInstance(b.getBagValue());
        PrivateKey privKey = unwrapKey(eIn.getEncryptionAlgorithm(), eIn.getEncryptedData(), password, wrongPKCS12Zero);

        //
        // set the attributes on the key
        //
        String alias = null;
        ASN1OctetString localId = null;

        if (b.getBagAttributes() != null)
        {
            Enumeration e = b.getBagAttributes().getObjects();
            while (e.hasMoreElements())
            {
                ASN1Sequence sq = (ASN1Sequence)e.nextElement();
                ASN1ObjectIdentifier aOid = (ASN1ObjectIdentifier)sq.getObjectAt(0);
                ASN1Set attrSet = (ASN1Set)sq.getObjectAt(1);
                ASN1Primitive attr = null;

                if (attrSet.size() > 0)
                {
                    attr = (ASN1Primitive)attrSet.getObjectAt(0);

                    if (privKey instanceof PKCS12BagAttributeCarrier)
                    {
                        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)privKey;
                        ASN1Encodable existing = bagAttr.getBagAttribute(aOid);
                        if (existing != null)
                        {
                            // OK, but the value has to be the same
                            if (!existing.toASN1Primitive().equals(attr))
                            {
                                throw new IOException(
                                    "attempt to add existing attribute with different value");
                            }
                        }
                        else
                        {
                            bagAttr.setBagAttribute(aOid, attr);
                        }
                    }
                }

                if (aOid.equals(pkcs_9_at_friendlyName))
                {
                    alias = ((ASN1BMPString)attr).getString();
                    keys.put(alias, privKey);
                }
                else if (aOid.equals(pkcs_9_at_localKeyId))
                {
                    localId = (ASN1OctetString)attr;
                }
            }
        }

        if (localId != null)
        {
            String name = new String(Hex.encode(localId.getOctets()));

            if (alias == null)
            {
                keys.put(name, privKey);
            }
            else
            {
                localIds.put(alias, name);
            }
            return false;  // key properly marked
        }
        else
        {
            keys.put("unmarked", privKey);
            return true;  // key properly marked
        }
    }

    private void processKeyBag(SafeBag b)
        throws IOException
    {
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo kInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(b.getBagValue());
        PrivateKey privKey = BouncyCastleProvider.getPrivateKey(kInfo);

        //
        // set the attributes on the key
        //
        String alias = null;
        ASN1OctetString localId = null;

        if (privKey instanceof PKCS12BagAttributeCarrier)
        {
            PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier)privKey;

            Enumeration e = b.getBagAttributes().getObjects();
            while (e.hasMoreElements())
            {
                ASN1Sequence sq = ASN1Sequence.getInstance(e.nextElement());
                ASN1ObjectIdentifier aOid = ASN1ObjectIdentifier.getInstance(sq.getObjectAt(0));
                ASN1Set attrSet = ASN1Set.getInstance(sq.getObjectAt(1));
                ASN1Primitive attr = null;

                if (attrSet.size() > 0)
                {
                    attr = (ASN1Primitive)attrSet.getObjectAt(0);

                    ASN1Encodable existing = bagAttr.getBagAttribute(aOid);
                    if (existing != null)
                    {
                        // OK, but the value has to be the same
                        if (!existing.toASN1Primitive().equals(attr))
                        {
                            throw new IOException(
                                "attempt to add existing attribute with different value");
                        }
                    }
                    else
                    {
                        bagAttr.setBagAttribute(aOid, attr);
                    }

                    if (aOid.equals(pkcs_9_at_friendlyName))
                    {
                        alias = ((ASN1BMPString)attr).getString();
                        keys.put(alias, privKey);
                    }
                    else if (aOid.equals(pkcs_9_at_localKeyId))
                    {
                        localId = (ASN1OctetString)attr;
                    }
                }
            }
        }

        String name = new String(Hex.encode(localId.getOctets()));

        if (alias == null)
        {
            keys.put(name, privKey);
        }
        else
        {
            localIds.put(alias, name);
        }
    }

    private int validateIterationCount(BigInteger i)
    {
        int count = BigIntegers.intValueExact(i);

        if (count < 0)
        {
            throw new IllegalStateException("negative iteration count found");
        }

        BigInteger maxValue = Properties.asBigInteger(PKCS12_MAX_IT_COUNT_PROPERTY);
        if (maxValue != null)
        {
            if (BigIntegers.intValueExact(maxValue) < count)
            {
                throw new IllegalStateException("iteration count " + count + " greater than "
                    + BigIntegers.intValueExact(maxValue));
            }
        }

        return count;
    }

    private ASN1Primitive getAlgParams(ASN1ObjectIdentifier algorithm)
    {
         if (algorithm.equals(NISTObjectIdentifiers.id_aes128_CBC)
            || algorithm.equals(NISTObjectIdentifiers.id_aes256_CBC))
         {
             byte[] iv = new byte[16];
             
             random.nextBytes(iv);

             return new DEROctetString(iv);
         }
         else if (algorithm.equals(NISTObjectIdentifiers.id_aes128_GCM)
              || algorithm.equals(NISTObjectIdentifiers.id_aes256_GCM))
         {
             byte[] nonce = new byte[12];

             random.nextBytes(nonce);

             return new GCMParameters(nonce, 16).toASN1Primitive();
         }

         throw new IllegalStateException("unknown encryption OID in getAlgParams()");
    }
    
    public void engineStore(LoadStoreParameter param)
        throws IOException,
        NoSuchAlgorithmException, CertificateException
    {
        if (param == null)
        {
            throw new IllegalArgumentException("'param' arg cannot be null");
        }

        if (!(param instanceof PKCS12StoreParameter || param instanceof JDKPKCS12StoreParameter))
        {
            throw new IllegalArgumentException(
                "No support for 'param' of type " + param.getClass().getName());
        }

        PKCS12StoreParameter bcParam;

        if (param instanceof PKCS12StoreParameter)
        {
            bcParam = (PKCS12StoreParameter)param;
        }
        else
        {
            bcParam = new PKCS12StoreParameter(((JDKPKCS12StoreParameter)param).getOutputStream(),
                param.getProtectionParameter(), ((JDKPKCS12StoreParameter)param).isUseDEREncoding(),
                    ((JDKPKCS12StoreParameter)param).isOverwriteFriendlyName());
        }

        char[] password;
        ProtectionParameter protParam = param.getProtectionParameter();
        if (protParam == null)
        {
            password = null;
        }
        else if (protParam instanceof KeyStore.PasswordProtection)
        {
            password = ((KeyStore.PasswordProtection)protParam).getPassword();
        }
        else
        {
            throw new IllegalArgumentException(
                "No support for protection parameter of type " + protParam.getClass().getName());
        }

        doStore(bcParam.getOutputStream(), password, bcParam.isForDEREncoding(), bcParam.isOverwriteFriendlyName());
    }

    public void engineStore(OutputStream stream, char[] password)
        throws IOException
    {
        doStore(stream, password, false, true);
    }

    private void syncFriendlyName()
    {
        // TODO:delete comment
        //  Since we cannot add any function to the KeyStore Api we will run code when saving the store
        // to sync the friendlyNames with Alias depending on the storeParameter
        /*
         *     @Override
         *     public void setFriendlyName(String alias, String newFriendlyName, char[] password) throws UnrecoverableKeyException, NoSuchAlgorithmException
         *     {
         *         if (alias.equals(newFriendlyName))
         *         {
         *             return;
         *         }
         *
         *         if (engineIsKeyEntry(alias))
         *         {
         *             ((PKCS12BagAttributeCarrier)engineGetKey(alias, password)).setFriendlyName(newFriendlyName);
         *             keyCerts.put(newFriendlyName, keyCerts.get(alias));
         *             keyCerts.remove(alias);
         *         }
         *         else
         *         {
         *             certs.put(newFriendlyName, certs.get(alias));
         *             certs.remove(alias);
         *         }
         *         ((PKCS12BagAttributeCarrier)engineGetCertificate(alias)).setFriendlyName(newFriendlyName);
         *
         *     }
         */
        Enumeration cs = keys.keys();

        while (cs.hasMoreElements())
        {
            String keyId = (String) cs.nextElement();
            PrivateKey key = (PrivateKey)keys.get(keyId);

            if (key instanceof PKCS12BagAttributeCarrier)
            {
                ASN1Encodable friendlyName = ((PKCS12BagAttributeCarrier)key).getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName);
                if (friendlyName != null && !keyId.equals(friendlyName.toString()))
                {
                    keys.put(friendlyName.toString(), key);
                    keys.remove(keyId);
                }
            }
        }

        cs = certs.keys();

        while (cs.hasMoreElements())
        {
            String certId = (String) cs.nextElement();
            Certificate cert = (Certificate)certs.get(certId);

            if (cert instanceof PKCS12BagAttributeCarrier)
            {
                ASN1Encodable friendlyName = ((PKCS12BagAttributeCarrier)cert).getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName);
                if (friendlyName != null && !certId.equals(friendlyName.toString()))
                {
                    certs.put(friendlyName.toString(), cert);
                    certs.remove(certId);
                }
            }
        }
        cs = keyCerts.keys();

        while (cs.hasMoreElements())
        {
            String certId = (String) cs.nextElement();
            Certificate cert = (Certificate)keyCerts.get(certId);

            if (cert instanceof PKCS12BagAttributeCarrier)
            {
                ASN1Encodable friendlyName = ((PKCS12BagAttributeCarrier)cert).getBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName);
                if (friendlyName != null && !certId.equals(friendlyName.toString()))
                {
                    keyCerts.put(friendlyName.toString(), cert);
                    keyCerts.remove(certId);
                }
            }
        }
    }

    private void doStore(OutputStream stream, char[] password, boolean useDEREncoding, boolean overwriteFriendlyName)
        throws IOException
    {
        if (!overwriteFriendlyName)
        {
            syncFriendlyName();
        }

        if (keys.size() == 0)
        {
            if (password == null)
            {
                Enumeration cs = certs.keys();

                ASN1EncodableVector certSeq = new ASN1EncodableVector();

                while (cs.hasMoreElements())
                {
                    try
                    {
                        String certId = (String)cs.nextElement();
                        Certificate cert = (Certificate)certs.get(certId);

                        SafeBag sBag = createSafeBag(certId, cert, overwriteFriendlyName);

                        certSeq.add(sBag);
                    }
                    catch (CertificateEncodingException e)
                    {
                        throw new IOException("Error encoding certificate: " + e.toString());
                    }
                }

                if (useDEREncoding)
                {
                    ContentInfo bagInfo = new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new DERSequence(certSeq).getEncoded()));

                    Pfx pfx = new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new DERSequence(bagInfo).getEncoded())), null);

                    pfx.encodeTo(stream, ASN1Encoding.DER);
                }
                else
                {
                    ContentInfo bagInfo = new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString(new BERSequence(certSeq).getEncoded()));

                    Pfx pfx = new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString(new BERSequence(bagInfo).getEncoded())), null);

                    pfx.encodeTo(stream, ASN1Encoding.BER);
                }

                return;
            }
        }
        else
        {
            if (password == null)
            {
                throw new NullPointerException("no password supplied for PKCS#12 KeyStore");
            }
        }

        //
        // handle the key
        //
        ASN1EncodableVector keyS = new ASN1EncodableVector();

        Enumeration ks = keys.keys();

        while (ks.hasMoreElements())
        {
            byte[] kSalt = new byte[SALT_SIZE];

            random.nextBytes(kSalt);

            String name = (String)ks.nextElement();
            PrivateKey privKey = (PrivateKey)keys.get(name);
            AlgorithmIdentifier kAlgId;
            byte[] kBytes;
            if (isPBKDF2(keyAlgorithm))
            {
                // TODO: keySize hard coded to 256 bits
                PBKDF2Params kParams = new PBKDF2Params(kSalt, MIN_ITERATIONS, getKeyLength(keyAlgorithm), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));
                EncryptionScheme encScheme = new EncryptionScheme(keyAlgorithm, getAlgParams(keyAlgorithm));
                kAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, new PBES2Parameters(
                    new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, kParams), encScheme));
                kBytes = wrapKey(encScheme, privKey, kParams, password);
            }
            else
            {
                PKCS12PBEParams kParams = new PKCS12PBEParams(kSalt, MIN_ITERATIONS);
                kBytes = wrapKey(keyAlgorithm.getId(), privKey, kParams, password);
                kAlgId = new AlgorithmIdentifier(keyAlgorithm, kParams.toASN1Primitive());
            }
            org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo kInfo = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(kAlgId, kBytes);
            boolean attrSet = false;
            ASN1EncodableVector kName = new ASN1EncodableVector();

            if (privKey instanceof PKCS12BagAttributeCarrier)
            {
                PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)privKey;
                //
                // make sure we are using the local alias on store
                //
                ASN1BMPString nm = (ASN1BMPString)bagAttrs.getBagAttribute(pkcs_9_at_friendlyName);
                if (overwriteFriendlyName)
                {
                    if (nm == null || !nm.getString().equals(name))
                    {
                        bagAttrs.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(name));
                    }
                }

                //
                // make sure we have a local key-id
                //
                if (bagAttrs.getBagAttribute(pkcs_9_at_localKeyId) == null)
                {
                    Certificate ct = engineGetCertificate(name);

                    bagAttrs.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(ct.getPublicKey()));
                }

                Enumeration e = bagAttrs.getBagAttributeKeys();

                while (e.hasMoreElements())
                {
                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                    ASN1EncodableVector kSeq = new ASN1EncodableVector();

                    kSeq.add(oid);
                    kSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));

                    attrSet = true;

                    kName.add(new DERSequence(kSeq));
                }
            }

            if (!attrSet)
            {
                //
                // set a default friendly name (from the key id) and local id
                //
                ASN1EncodableVector kSeq = new ASN1EncodableVector();
                Certificate ct = engineGetCertificate(name);

                kSeq.add(pkcs_9_at_localKeyId);
                kSeq.add(new DERSet(createSubjectKeyId(ct.getPublicKey())));

                kName.add(new DERSequence(kSeq));

                kSeq = new ASN1EncodableVector();

                kSeq.add(pkcs_9_at_friendlyName);
                kSeq.add(new DERSet(new DERBMPString(name)));

                kName.add(new DERSequence(kSeq));
            }

            SafeBag kBag = new SafeBag(pkcs8ShroudedKeyBag, kInfo.toASN1Primitive(), new DERSet(kName));
            keyS.add(kBag);
        }

        byte[] keySEncoded = new DERSequence(keyS).getEncoded(ASN1Encoding.DER);
        BEROctetString keyString = new BEROctetString(keySEncoded);

        //
        // certificate processing
        //
        byte[] cSalt = new byte[SALT_SIZE];

        random.nextBytes(cSalt);

        ASN1EncodableVector certSeq = new ASN1EncodableVector();
        AlgorithmIdentifier cAlgId;
        if (isPBKDF2(certAlgorithm))
        {
            PBKDF2Params cParams = new PBKDF2Params(cSalt, MIN_ITERATIONS, getKeyLength(certAlgorithm), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE));
            cAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, new PBES2Parameters(
                new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, cParams), new EncryptionScheme(certAlgorithm, getAlgParams(certAlgorithm))));
        }
        else
        {
            PKCS12PBEParams cParams = new PKCS12PBEParams(cSalt, MIN_ITERATIONS);
            cAlgId = new AlgorithmIdentifier(certAlgorithm, cParams.toASN1Primitive());
        }
        Hashtable doneCerts = new Hashtable();

        Enumeration cs = keys.keys();
        while (cs.hasMoreElements())
        {
            try
            {
                String name = (String)cs.nextElement();
                Certificate cert = engineGetCertificate(name);
                boolean cAttrSet = false;
                CertBag cBag = new CertBag(
                    x509Certificate,
                    new DEROctetString(cert.getEncoded()));
                ASN1EncodableVector fName = new ASN1EncodableVector();

                if (cert instanceof PKCS12BagAttributeCarrier)
                {
                    PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)cert;
                    //
                    // make sure we are using the local alias on store
                    //
                    ASN1BMPString nm = (ASN1BMPString)bagAttrs.getBagAttribute(pkcs_9_at_friendlyName);
                    if (overwriteFriendlyName)
                    {
                        if (nm == null || !nm.getString().equals(name))
                        {
                            bagAttrs.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(name));
                        }
                    }

                    //
                    // make sure we have a local key-id
                    //
                    if (bagAttrs.getBagAttribute(pkcs_9_at_localKeyId) == null)
                    {
                        bagAttrs.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(cert.getPublicKey()));
                    }

                    Enumeration e = bagAttrs.getBagAttributeKeys();

                    while (e.hasMoreElements())
                    {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
                        ASN1EncodableVector fSeq = new ASN1EncodableVector();

                        fSeq.add(oid);
                        fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                        fName.add(new DERSequence(fSeq));

                        cAttrSet = true;
                    }
                }

                if (!cAttrSet)
                {
                    ASN1EncodableVector fSeq = new ASN1EncodableVector();

                    fSeq.add(pkcs_9_at_localKeyId);
                    fSeq.add(new DERSet(createSubjectKeyId(cert.getPublicKey())));
                    fName.add(new DERSequence(fSeq));

                    fSeq = new ASN1EncodableVector();

                    fSeq.add(pkcs_9_at_friendlyName);
                    fSeq.add(new DERSet(new DERBMPString(name)));

                    fName.add(new DERSequence(fSeq));
                }

                SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

                certSeq.add(sBag);

                doneCerts.put(cert, cert);
            }
            catch (CertificateEncodingException e)
            {
                throw new IOException("Error encoding certificate: " + e.toString());
            }
        }

        cs = certs.keys();
        while (cs.hasMoreElements())
        {
            try
            {
                String certId = (String)cs.nextElement();
                Certificate cert = (Certificate)certs.get(certId);

                if (keys.get(certId) != null)
                {
                    continue;
                }

                SafeBag sBag = createSafeBag(certId, cert, overwriteFriendlyName);

                certSeq.add(sBag);

                doneCerts.put(cert, cert);
            }
            catch (CertificateEncodingException e)
            {
                throw new IOException("Error encoding certificate: " + e.toString());
            }
        }

        Set usedSet = getUsedCertificateSet();

        cs = chainCerts.keys();
        while (cs.hasMoreElements())
        {
            try
            {
                CertId certId = (CertId)cs.nextElement();
                Certificate cert = (Certificate)chainCerts.get(certId);

                if (!usedSet.contains(cert))
                {
                    continue;
                }

                if (doneCerts.get(cert) != null)
                {
                    continue;
                }

                CertBag cBag = new CertBag(
                    x509Certificate,
                    new DEROctetString(cert.getEncoded()));
                ASN1EncodableVector fName = new ASN1EncodableVector();

                if (cert instanceof PKCS12BagAttributeCarrier)
                {
                    PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)cert;
                    Enumeration e = bagAttrs.getBagAttributeKeys();

                    while (e.hasMoreElements())
                    {
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

                        // a certificate not immediately linked to a key doesn't require
                        // a localKeyID and will confuse some PKCS12 implementations.
                        //
                        // If we find one, we'll prune it out.
                        if (oid.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId))
                        {
                            continue;
                        }

                        ASN1EncodableVector fSeq = new ASN1EncodableVector();

                        fSeq.add(oid);
                        fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                        fName.add(new DERSequence(fSeq));
                    }
                }

                SafeBag sBag = new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));

                certSeq.add(sBag);
            }
            catch (CertificateEncodingException e)
            {
                throw new IOException("Error encoding certificate: " + e.toString());
            }
        }

        byte[] certSeqEncoded = new DERSequence(certSeq).getEncoded(ASN1Encoding.DER);
        byte[] certBytes = cryptData(true, cAlgId, password, false, certSeqEncoded);
        EncryptedData cInfo = new EncryptedData(data, cAlgId, new BEROctetString(certBytes));

        ContentInfo[] info = new ContentInfo[]
            {
                new ContentInfo(data, keyString),
                new ContentInfo(encryptedData, cInfo.toASN1Primitive())
            };

        AuthenticatedSafe auth = new AuthenticatedSafe(info);

        byte[] pkg = auth.getEncoded(useDEREncoding ? ASN1Encoding.DER : ASN1Encoding.BER);

        ContentInfo mainInfo = new ContentInfo(data, new BEROctetString(pkg));

        //
        // create the mac
        //
        byte[] mSalt = new byte[saltLength];

        random.nextBytes(mSalt);

        byte[] data = ((ASN1OctetString)mainInfo.getContent()).getOctets();

        MacData mData;

        if (keyAlgorithm.equals(NISTObjectIdentifiers.id_aes256_GCM))
        {
            mData = null;
        }
        else
        {
            try
            {
                byte[] res = calculatePbeMac(macAlgorithm.getAlgorithm(), mSalt, itCount, password, false, data);

                DigestInfo dInfo = new DigestInfo(macAlgorithm, res);

                mData = new MacData(dInfo, mSalt, itCount);
            }
            catch (Exception e)
            {
                throw new IOException("error constructing MAC: " + e.toString());
            }
        }

        //
        // output the Pfx
        //
        Pfx pfx = new Pfx(mainInfo, mData);

        pfx.encodeTo(stream, useDEREncoding ? ASN1Encoding.DER : ASN1Encoding.BER);
    }

    private SafeBag createSafeBag(String certId, Certificate cert, boolean overwriteFriendlyName)
        throws CertificateEncodingException
    {
        CertBag cBag = new CertBag(
            x509Certificate,
            new DEROctetString(cert.getEncoded()));
        ASN1EncodableVector fName = new ASN1EncodableVector();

        boolean cAttrSet = false;
        if (cert instanceof PKCS12BagAttributeCarrier)
        {
            PKCS12BagAttributeCarrier bagAttrs = (PKCS12BagAttributeCarrier)cert;
            //
            // make sure we are using the local alias on store
            //
            ASN1BMPString nm = (ASN1BMPString)bagAttrs.getBagAttribute(pkcs_9_at_friendlyName);
            if (overwriteFriendlyName)
            {
                if (nm == null || !nm.getString().equals(certId))
                {
                    if (certId != null)
                    {
                        bagAttrs.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(certId));
                    }
                }
            }

            Enumeration e = bagAttrs.getBagAttributeKeys();

            while (e.hasMoreElements())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

                // a certificate not immediately linked to a key doesn't require
                // a localKeyID and will confuse some PKCS12 implementations.
                //
                // If we find one, we'll prune it out.
                if (oid.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId))
                {
                    continue;
                }

                if (oid.equals(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage))
                {
                    continue;
                }
                
                ASN1EncodableVector fSeq = new ASN1EncodableVector();

                fSeq.add(oid);
                fSeq.add(new DERSet(bagAttrs.getBagAttribute(oid)));
                fName.add(new DERSequence(fSeq));

                cAttrSet = true;
            }
        }

        if (!cAttrSet)
        {
            ASN1EncodableVector fSeq = new ASN1EncodableVector();

            fSeq.add(pkcs_9_at_friendlyName);
            fSeq.add(new DERSet(new DERBMPString(certId)));

            fName.add(new DERSequence(fSeq));
        }

        // add the trusted usage attribute - needed for Oracle key stores
        if (cert instanceof X509Certificate)
        {
            TBSCertificate tbsCert = TBSCertificate.getInstance(((X509Certificate)cert).getTBSCertificate());

            ASN1OctetString eku = Extensions.getExtensionValue(tbsCert.getExtensions(),
                Extension.extendedKeyUsage);

            DERSet attrValue;
            if (eku != null)
            {
                attrValue = new DERSet(ExtendedKeyUsage.getInstance(eku.getOctets()).getUsages());
            }
            else
            {
                attrValue = new DERSet(KeyPurposeId.anyExtendedKeyUsage);
            }

            fName.add(new DERSequence(MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage, attrValue));
        }

        return new SafeBag(certBag, cBag.toASN1Primitive(), new DERSet(fName));
    }

    private Set getUsedCertificateSet()
    {
        Set usedSet = new HashSet();

        for (Enumeration en = keys.keys(); en.hasMoreElements(); )
        {
            String alias = (String)en.nextElement();

            Certificate[] certs = engineGetCertificateChain(alias);

            for (int i = 0; i != certs.length; i++)
            {
                usedSet.add(certs[i]);
            }
        }

        for (Enumeration en = certs.keys(); en.hasMoreElements(); )
        {
            String alias = (String)en.nextElement();

            Certificate cert = engineGetCertificate(alias);

            usedSet.add(cert);
        }

        return usedSet;
    }

    private byte[] calculatePbeMac(
        ASN1ObjectIdentifier oid,
        byte[] salt,
        int itCount,
        char[] password,
        boolean wrongPkcs12Zero,
        byte[] data)
        throws Exception
    {
        if (PKCSObjectIdentifiers.id_PBMAC1.equals(oid))
        {
            PBMAC1Params pbmac1Params = PBMAC1Params.getInstance(macAlgorithm.getParameters());
            if (pbmac1Params == null)
            {
                throw new IOException("If the DigestAlgorithmIdentifier is id-PBMAC1, then the parameters field must contain valid PBMAC1-params parameters.");
            }
            if (PKCSObjectIdentifiers.id_PBKDF2.equals(pbmac1Params.getKeyDerivationFunc().getAlgorithm()))
            {
                PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbmac1Params.getKeyDerivationFunc().getParameters());
                if (pbkdf2Params.getKeyLength() == null)
                {
                    throw new IOException("Key length must be present when using PBMAC1.");
                }
                final HMac hMac = new HMac(getPrf(pbmac1Params.getMessageAuthScheme().getAlgorithm()));

                PBEParametersGenerator generator = new PKCS5S2ParametersGenerator(getPrf(pbkdf2Params.getPrf().getAlgorithm()));

                generator.init(
                    Strings.toUTF8ByteArray(password),
                    pbkdf2Params.getSalt(),
                    BigIntegers.intValueExact(pbkdf2Params.getIterationCount()));

                CipherParameters key = generator.generateDerivedParameters(BigIntegers.intValueExact(pbkdf2Params.getKeyLength()) * 8);

                Arrays.clear(generator.getPassword());

                hMac.init(key);
                hMac.update(data, 0, data.length);
                byte[] res = new byte[hMac.getMacSize()];
                hMac.doFinal(res, 0);
                return res;
            }
        }
        
        PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
        PKCS12Key key = new PKCS12Key(password, wrongPkcs12Zero);

        try
        {
            Mac mac = helper.createMac(oid.getId());

            mac.init(key, defParams);
            mac.update(data);

            return mac.doFinal();
        }
        finally
        {
            Arrays.clear(key.getPassword());
        }
    }

    private static Digest getPrf(ASN1ObjectIdentifier prfId)
    {
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(prfId))
        {
            return new SHA256Digest();
        }
        else if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(prfId))
        {
            return new SHA512Digest();
        }
        else
        {
            throw new IllegalArgumentException("unknown prf id " + prfId);
        }
    }

    public static class BCPKCS12KeyStore
        extends AdaptingKeyStoreSpi
    {
        public BCPKCS12KeyStore()
        {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC));
        }
    }

    public static class BCPKCS12KeyStore3DES
        extends AdaptingKeyStoreSpi
    {
        public BCPKCS12KeyStore3DES()
        {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC));
        }
    }

    public static class BCPKCS12KeyStoreAES256
        extends AdaptingKeyStoreSpi
    {
        public BCPKCS12KeyStoreAES256()
        {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes128_CBC));
        }
    }

    public static class BCPKCS12KeyStoreAES256GCM
        extends AdaptingKeyStoreSpi
    {
        public BCPKCS12KeyStoreAES256GCM()
        {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes128_GCM));
        }
    }

    public static class DefPKCS12KeyStore
        extends AdaptingKeyStoreSpi
    {
        public DefPKCS12KeyStore()
        {
            super(new DefaultJcaJceHelper(), new PKCS12KeyStoreSpi(new DefaultJcaJceHelper(), pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC));
        }
    }

    public static class DefPKCS12KeyStore3DES
        extends AdaptingKeyStoreSpi
    {
        public DefPKCS12KeyStore3DES()
        {
            super(new DefaultJcaJceHelper(), new PKCS12KeyStoreSpi(new DefaultJcaJceHelper(), pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd3_KeyTripleDES_CBC));
        }
    }

    public static class DefPKCS12KeyStoreAES256
        extends AdaptingKeyStoreSpi
    {
        public DefPKCS12KeyStoreAES256()
        {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), NISTObjectIdentifiers.id_aes256_CBC, NISTObjectIdentifiers.id_aes128_CBC));
        }
    }

    public static class DefPKCS12KeyStoreAES256GCM
        extends AdaptingKeyStoreSpi
    {
        public DefPKCS12KeyStoreAES256GCM()
        {
            super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), NISTObjectIdentifiers.id_aes256_GCM, NISTObjectIdentifiers.id_aes128_GCM));
        }
    }

    private static class IgnoresCaseHashtable
    {
        private Hashtable orig = new Hashtable();
        private Hashtable keys = new Hashtable();

        public void put(String key, Object value)
        {
            String lower = (key == null) ? null : Strings.toLowerCase(key);
            String k = (String)keys.get(lower);
            if (k != null)
            {
                orig.remove(k);
            }

            keys.put(lower, key);
            orig.put(key, value);
        }

        public Enumeration keys()
        {
            return new Hashtable(orig).keys();
        }

        public Object remove(String alias)
        {
            String k = (String)keys.remove(alias == null ? null : Strings.toLowerCase(alias));
            if (k == null)
            {
                return null;
            }

            return orig.remove(k);
        }

        public Object get(String alias)
        {
            String k = (String)keys.get(alias == null ? null : Strings.toLowerCase(alias));
            if (k == null)
            {
                return null;
            }

            return orig.get(k);
        }

        public Enumeration elements()
        {
            return orig.elements();
        }

        public int size()
        {
            return orig.size();
        }
    }

    private static class DefaultSecretKeyProvider
    {
        private final Map KEY_SIZES;

        DefaultSecretKeyProvider()
        {
            Map keySizes = new HashMap();

            keySizes.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));

            keySizes.put(PKCSObjectIdentifiers.des_EDE3_CBC, Integers.valueOf(192));

            keySizes.put(NISTObjectIdentifiers.id_aes128_CBC, Integers.valueOf(128));
            keySizes.put(NISTObjectIdentifiers.id_aes192_CBC, Integers.valueOf(192));
            keySizes.put(NISTObjectIdentifiers.id_aes256_CBC, Integers.valueOf(256));

            keySizes.put(NISTObjectIdentifiers.id_aes128_GCM, Integers.valueOf(128));
            keySizes.put(NISTObjectIdentifiers.id_aes256_GCM, Integers.valueOf(256));

            keySizes.put(NTTObjectIdentifiers.id_camellia128_cbc, Integers.valueOf(128));
            keySizes.put(NTTObjectIdentifiers.id_camellia192_cbc, Integers.valueOf(192));
            keySizes.put(NTTObjectIdentifiers.id_camellia256_cbc, Integers.valueOf(256));

            keySizes.put(CryptoProObjectIdentifiers.gostR28147_gcfb, Integers.valueOf(256));

            KEY_SIZES = Collections.unmodifiableMap(keySizes);
        }

        public int getKeySize(AlgorithmIdentifier algorithmIdentifier)
        {
            // TODO: not all ciphers/oid relationships are this simple.
            Integer keySize = (Integer)KEY_SIZES.get(algorithmIdentifier.getAlgorithm());

            if (keySize != null)
            {
                return keySize.intValue();
            }

            return -1;
        }
    }
}
