package org.bouncycastle.jcajce.provider.keystore.bcfks;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.EncryptedObjectStoreData;
import org.bouncycastle.asn1.bc.EncryptedPrivateKeyData;
import org.bouncycastle.asn1.bc.EncryptedSecretKeyData;
import org.bouncycastle.asn1.bc.ObjectData;
import org.bouncycastle.asn1.bc.ObjectDataSequence;
import org.bouncycastle.asn1.bc.ObjectStore;
import org.bouncycastle.asn1.bc.ObjectStoreData;
import org.bouncycastle.asn1.bc.ObjectStoreIntegrityCheck;
import org.bouncycastle.asn1.bc.PbkdMacIntegrityCheck;
import org.bouncycastle.asn1.bc.SecretKeyData;
import org.bouncycastle.asn1.cms.CCMParameters;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.PBKDFConfig;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jcajce.BCFKSStoreParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

class BcFKSKeyStoreSpi
    extends KeyStoreSpi
{
    private static final Map<String, ASN1ObjectIdentifier> oidMap = new HashMap<String, ASN1ObjectIdentifier>();
    private static final Map<ASN1ObjectIdentifier, String> publicAlgMap = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        // Note: AES handled inline
        oidMap.put("DESEDE", OIWObjectIdentifiers.desEDE);
        oidMap.put("TRIPLEDES", OIWObjectIdentifiers.desEDE);
        oidMap.put("TDEA", OIWObjectIdentifiers.desEDE);
        oidMap.put("HMACSHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
        oidMap.put("HMACSHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);
        oidMap.put("HMACSHA256", PKCSObjectIdentifiers.id_hmacWithSHA256);
        oidMap.put("HMACSHA384", PKCSObjectIdentifiers.id_hmacWithSHA384);
        oidMap.put("HMACSHA512", PKCSObjectIdentifiers.id_hmacWithSHA512);
        oidMap.put("SEED", KISAObjectIdentifiers.id_seedCBC);

        oidMap.put("CAMELLIA.128", NTTObjectIdentifiers.id_camellia128_cbc);
        oidMap.put("CAMELLIA.192", NTTObjectIdentifiers.id_camellia192_cbc);
        oidMap.put("CAMELLIA.256", NTTObjectIdentifiers.id_camellia256_cbc);

        oidMap.put("ARIA.128", NSRIObjectIdentifiers.id_aria128_cbc);
        oidMap.put("ARIA.192", NSRIObjectIdentifiers.id_aria192_cbc);
        oidMap.put("ARIA.256", NSRIObjectIdentifiers.id_aria256_cbc);

        publicAlgMap.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        publicAlgMap.put(X9ObjectIdentifiers.id_ecPublicKey, "EC");
        publicAlgMap.put(OIWObjectIdentifiers.elGamalAlgorithm, "DH");
        publicAlgMap.put(PKCSObjectIdentifiers.dhKeyAgreement, "DH");
        publicAlgMap.put(X9ObjectIdentifiers.id_dsa, "DSA");
    }

    private static String getPublicKeyAlg(ASN1ObjectIdentifier oid)
    {
        String algName = (String)publicAlgMap.get(oid);

        if (algName != null)
        {
            return algName;
        }

        return oid.getId();
    }

    private final static BigInteger CERTIFICATE = BigInteger.valueOf(0);
    private final static BigInteger PRIVATE_KEY = BigInteger.valueOf(1);
    private final static BigInteger SECRET_KEY = BigInteger.valueOf(2);
    private final static BigInteger PROTECTED_PRIVATE_KEY = BigInteger.valueOf(3);
    private final static BigInteger PROTECTED_SECRET_KEY = BigInteger.valueOf(4);

    private final BouncyCastleProvider provider;
    private final Map<String, ObjectData> entries = new HashMap<String, ObjectData>();
    private final Map<String, PrivateKey> privateKeyCache = new HashMap<String, PrivateKey>();

    private AlgorithmIdentifier hmacAlgorithm;
    private KeyDerivationFunc hmacPkbdAlgorithm;
    private Date creationDate;
    private Date lastModifiedDate;

    BcFKSKeyStoreSpi(BouncyCastleProvider provider)
    {
        this.provider = provider;
    }

    public Key engineGetKey(String alias, char[] password)
        throws NoSuchAlgorithmException, UnrecoverableKeyException
    {
        ObjectData ent = (ObjectData)entries.get(alias);

        if (ent != null)
        {
            if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
            {
                PrivateKey cachedKey = (PrivateKey)privateKeyCache.get(alias);
                if (cachedKey != null)
                {
                    return cachedKey;
                }

                EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfo.getInstance(encPrivData.getEncryptedPrivateKeyInfo());

                try
                {
                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(decryptData("PRIVATE_KEY_ENCRYPTION", encInfo.getEncryptionAlgorithm(), password, encInfo.getEncryptedData()));

                    KeyFactory kFact;
                    if (provider != null)
                    {
                        kFact = KeyFactory.getInstance(pInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), provider);
                    }
                    else
                    {
                        kFact = KeyFactory.getInstance(getPublicKeyAlg(pInfo.getPrivateKeyAlgorithm().getAlgorithm()));
                    }

                    PrivateKey privateKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(pInfo.getEncoded()));

                    // check that the key pair and the certificate public key are consistent
                    // TODO: new ConsistentKeyPair(engineGetCertificate(alias).getPublicKey(), privateKey);

                    privateKeyCache.put(alias, privateKey);

                    return privateKey;
                }
                catch (Exception e)
                {
                    throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover private key (" + alias + "): " + e.getMessage());
                }
            }
            else if (ent.getType().equals(SECRET_KEY) || ent.getType().equals(PROTECTED_SECRET_KEY))
            {
                EncryptedSecretKeyData encKeyData = EncryptedSecretKeyData.getInstance(ent.getData());

                try
                {
                    SecretKeyData keyData = SecretKeyData.getInstance(decryptData("SECRET_KEY_ENCRYPTION", encKeyData.getKeyEncryptionAlgorithm(), password, encKeyData.getEncryptedKeyData()));
                    SecretKeyFactory kFact;
                    if (provider != null)
                    {
                        kFact = SecretKeyFactory.getInstance(keyData.getKeyAlgorithm().getId(), provider);
                    }
                    else
                    {
                        kFact = SecretKeyFactory.getInstance(keyData.getKeyAlgorithm().getId());
                    }

                    return kFact.generateSecret(new SecretKeySpec(keyData.getKeyBytes(), keyData.getKeyAlgorithm().getId()));
                }
                catch (Exception e)
                {
                    throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + alias + "): " + e.getMessage());
                }
            }
            else
            {
                throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + alias + "): type not recognized");
            }
        }

        return null;
    }

    public Certificate[] engineGetCertificateChain(String alias)
    {
        ObjectData ent = (ObjectData)entries.get(alias);

        if (ent != null)
        {
            if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
            {
                EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                org.bouncycastle.asn1.x509.Certificate[] certificates = encPrivData.getCertificateChain();
                Certificate[] chain = new X509Certificate[certificates.length];

                for (int i = 0; i != chain.length; i++)
                {
                    chain[i] = decodeCertificate(certificates[i]);
                }

                return chain;
            }
        }

        return null;
    }

    public Certificate engineGetCertificate(String s)
    {
        ObjectData ent = (ObjectData)entries.get(s);

        if (ent != null)
        {
            if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
            {
                EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                org.bouncycastle.asn1.x509.Certificate[] certificates = encPrivData.getCertificateChain();

                return decodeCertificate(certificates[0]);
            }
            else if (ent.getType().equals(CERTIFICATE))
            {
                return decodeCertificate(ent.getData());
            }
        }

        return null;
    }

    private Certificate decodeCertificate(Object cert)
    {
        if (provider != null)
        {
            try
            {
                CertificateFactory certFact = CertificateFactory.getInstance("X.509", provider);

                return certFact.generateCertificate(new ByteArrayInputStream(org.bouncycastle.asn1.x509.Certificate.getInstance(cert).getEncoded()));
            }
            catch (Exception e)
            {
                return null;
            }
        }
        else
        {
            try
            {
                CertificateFactory certFact = CertificateFactory.getInstance("X.509");

                return certFact.generateCertificate(new ByteArrayInputStream(org.bouncycastle.asn1.x509.Certificate.getInstance(cert).getEncoded()));
            }
            catch (Exception e)
            {
                return null;
            }
        }
    }

    public Date engineGetCreationDate(String s)
    {
        ObjectData ent = (ObjectData)entries.get(s);

        if (ent != null)
        {
            try
            {
                // we return last modified as it represents date current state of entry was created
                return ent.getLastModifiedDate().getDate();
            }
            catch (ParseException e)
            {
                return new Date();     // it's here, but...
            }
        }

        return null;
    }

    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
        throws KeyStoreException
    {
        Date creationDate = new Date();
        Date lastEditDate = creationDate;

        ObjectData entry = (ObjectData)entries.get(alias);
        if (entry != null)
        {
            creationDate = extractCreationDate(entry, creationDate);
        }

        privateKeyCache.remove(alias);

        if (key instanceof PrivateKey)
        {
            if (chain == null)
            {
                throw new KeyStoreException("BCFKS KeyStore requires a certificate chain for private key storage.");
            }

            try
            {
                // check that the key pair and the certificate public are consistent
                // TODO: new ConsistentKeyPair(chain[0].getPublicKey(), (PrivateKey)key);

                byte[] encodedKey = key.getEncoded();

                KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, 256 / 8);
                byte[] keyBytes = generateKey(pbkdAlgId, "PRIVATE_KEY_ENCRYPTION", ((password != null) ? password : new char[0]), 32);

                Cipher c = createCipher("AES/CCM/NoPadding", keyBytes);

                byte[] encryptedKey = c.doFinal(encodedKey);
                AlgorithmParameters algParams = c.getParameters();

                PBES2Parameters pbeParams;
                if (algParams != null)
                {
                    pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters.getInstance(algParams.getEncoded())));
                }
                else    // AES KWP
                {
                    pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_wrap_pad, null));
                }

                EncryptedPrivateKeyInfo keyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbeParams), encryptedKey);

                EncryptedPrivateKeyData keySeq = createPrivateKeySequence(keyInfo, chain);

                entries.put(alias, new ObjectData(PRIVATE_KEY, alias, creationDate, lastEditDate, keySeq.getEncoded(), null));
            }
            catch (Exception e)
            {
                throw new ExtKeyStoreException("BCFKS KeyStore exception storing private key: " + e.toString(), e);
            }
        }
        else if (key instanceof SecretKey)
        {
            if (chain != null)
            {
                throw new KeyStoreException("BCFKS KeyStore cannot store certificate chain with secret key.");
            }

            try
            {
                byte[] encodedKey = key.getEncoded();

                KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, 256 / 8);
                byte[] keyBytes = generateKey(pbkdAlgId, "SECRET_KEY_ENCRYPTION", ((password != null) ? password : new char[0]), 32);

                Cipher c = createCipher("AES/CCM/NoPadding", keyBytes);

                String keyAlg = Strings.toUpperCase(key.getAlgorithm());
                SecretKeyData secKeyData;

                if (keyAlg.indexOf("AES") > -1)
                {
                    secKeyData = new SecretKeyData(NISTObjectIdentifiers.aes, encodedKey);
                }
                else
                {
                    ASN1ObjectIdentifier algOid = (ASN1ObjectIdentifier)oidMap.get(keyAlg);
                    if (algOid != null)
                    {
                        secKeyData = new SecretKeyData(algOid, encodedKey);
                    }
                    else
                    {
                        algOid = (ASN1ObjectIdentifier)oidMap.get(keyAlg + "." + (encodedKey.length * 8));
                        if (algOid != null)
                        {
                            secKeyData = new SecretKeyData(algOid, encodedKey);
                        }
                        else
                        {
                            throw new KeyStoreException("BCFKS KeyStore cannot recognize secret key (" + keyAlg + ") for storage.");
                        }
                    }
                }

                byte[] encryptedKey = c.doFinal(secKeyData.getEncoded());
                AlgorithmParameters algParams = c.getParameters();

                PBES2Parameters pbeParams;
                if (algParams != null)
                {
                    pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters.getInstance(algParams.getEncoded())));
                }
                else    // AES KWP
                {
                    pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_wrap_pad, null));
                }

                EncryptedSecretKeyData keyData = new EncryptedSecretKeyData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbeParams), encryptedKey);

                entries.put(alias, new ObjectData(SECRET_KEY, alias, creationDate, lastEditDate, keyData.getEncoded(), null));
            }
            catch (Exception e)
            {
                throw new ExtKeyStoreException("BCFKS KeyStore exception storing private key: " + e.toString(), e);
            }
        }
        else
        {
            throw new KeyStoreException("BCFKS KeyStore unable to recognize key.");
        }

        lastModifiedDate = lastEditDate;
    }

    private Cipher createCipher(String algorithm, byte[] keyBytes)
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
    {
        Cipher c;
        if (provider == null)
        {
            c = Cipher.getInstance(algorithm);
        }
        else
        {
            c = Cipher.getInstance(algorithm, provider);
        }

        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
        
        return c;
    }

    private SecureRandom getDefaultSecureRandom()
    {
        return CryptoServicesRegistrar.getSecureRandom();
    }

    private EncryptedPrivateKeyData createPrivateKeySequence(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] chain)
        throws CertificateEncodingException
    {
        org.bouncycastle.asn1.x509.Certificate[] certChain = new org.bouncycastle.asn1.x509.Certificate[chain.length];
        for (int i = 0; i != chain.length; i++)
        {
            certChain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(chain[i].getEncoded());
        }

        return new EncryptedPrivateKeyData(encryptedPrivateKeyInfo, certChain);
    }

    public void engineSetKeyEntry(String alias, byte[] keyBytes, Certificate[] chain)
        throws KeyStoreException
    {
        Date creationDate = new Date();
        Date lastEditDate = creationDate;

        ObjectData entry = (ObjectData)entries.get(alias);
        if (entry != null)
        {
            creationDate = extractCreationDate(entry, creationDate);
        }

        if (chain != null)
        {
            EncryptedPrivateKeyInfo encInfo;

            try
            {
                encInfo = EncryptedPrivateKeyInfo.getInstance(keyBytes);
            }
            catch (Exception e)
            {
                throw new ExtKeyStoreException("BCFKS KeyStore private key encoding must be an EncryptedPrivateKeyInfo.", e);
            }

            try
            {
                privateKeyCache.remove(alias);
                entries.put(alias, new ObjectData(PROTECTED_PRIVATE_KEY, alias, creationDate, lastEditDate, createPrivateKeySequence(encInfo, chain).getEncoded(), null));
            }
            catch (Exception e)
            {
                throw new ExtKeyStoreException("BCFKS KeyStore exception storing protected private key: " + e.toString(), e);
            }
        }
        else
        {
            try
            {
                entries.put(alias, new ObjectData(PROTECTED_SECRET_KEY, alias, creationDate, lastEditDate, keyBytes, null));
            }
            catch (Exception e)
            {
                throw new ExtKeyStoreException("BCFKS KeyStore exception storing protected private key: " + e.toString(), e);
            }
        }

        lastModifiedDate = lastEditDate;
    }

    public void engineSetCertificateEntry(String alias, Certificate certificate)
        throws KeyStoreException
    {
        ObjectData entry = (ObjectData)entries.get(alias);
        Date creationDate = new Date();
        Date lastEditDate = creationDate;

        if (entry != null)
        {
            if (!entry.getType().equals(CERTIFICATE))
            {
                throw new KeyStoreException("BCFKS KeyStore already has a key entry with alias " + alias);
            }

            creationDate = extractCreationDate(entry, creationDate);
        }

        try
        {
            entries.put(alias, new ObjectData(CERTIFICATE, alias, creationDate, lastEditDate, certificate.getEncoded(), null));
        }
        catch (CertificateEncodingException e)
        {
            throw new ExtKeyStoreException("BCFKS KeyStore unable to handle certificate: " + e.getMessage(), e);
        }

        lastModifiedDate = lastEditDate;
    }

    private Date extractCreationDate(ObjectData entry, Date creationDate)
    {
        try
        {
            creationDate = entry.getCreationDate().getDate();
        }
        catch (ParseException e)
        {
            // this should never happen, if it does we'll leave creation date unmodified and hope for the best.
        }
        return creationDate;
    }

    public void engineDeleteEntry(String alias)
        throws KeyStoreException
    {
        ObjectData entry = (ObjectData)entries.get(alias);

        if (entry == null)
        {
            return;
        }

        privateKeyCache.remove(alias);
        entries.remove(alias);

        lastModifiedDate = new Date();
    }

    public Enumeration<String> engineAliases()
    {
        final Iterator<String> it = new HashSet(entries.keySet()).iterator();

        return new Enumeration()
        {
            public boolean hasMoreElements()
            {
                return it.hasNext();
            }

            public Object nextElement()
            {
                return it.next();
            }
        };
    }

    public boolean engineContainsAlias(String alias)
    {
        if (alias == null)
        {
            throw new NullPointerException("alias value is null");
        }

        return entries.containsKey(alias);
    }

    public int engineSize()
    {
        return entries.size();
    }

    public boolean engineIsKeyEntry(String alias)
    {
        ObjectData ent = (ObjectData)entries.get(alias);

        if (ent != null)
        {
            BigInteger entryType = ent.getType();
            return entryType.equals(PRIVATE_KEY) || entryType.equals(SECRET_KEY)
                || entryType.equals(PROTECTED_PRIVATE_KEY) || entryType.equals(PROTECTED_SECRET_KEY);
        }

        return false;
    }

    public boolean engineIsCertificateEntry(String alias)
    {
        ObjectData ent = (ObjectData)entries.get(alias);

        if (ent != null)
        {
            return ent.getType().equals(CERTIFICATE);
        }

        return false;
    }

    public String engineGetCertificateAlias(Certificate certificate)
    {
        if (certificate == null)
        {
            return null;
        }

        byte[] encodedCert;
        try
        {
            encodedCert = certificate.getEncoded();
        }
        catch (CertificateEncodingException e)
        {
            return null;
        }

        for (Iterator<String> it = entries.keySet().iterator(); it.hasNext(); )
        {
            String alias = (String)it.next();
            ObjectData ent = (ObjectData)entries.get(alias);

            if (ent.getType().equals(CERTIFICATE))
            {
                if (Arrays.areEqual(ent.getData(), encodedCert))
                {
                    return alias;
                }
            }
            else if (ent.getType().equals(PRIVATE_KEY) || ent.getType().equals(PROTECTED_PRIVATE_KEY))
            {
                try
                {
                    EncryptedPrivateKeyData encPrivData = EncryptedPrivateKeyData.getInstance(ent.getData());
                    if (Arrays.areEqual(encPrivData.getCertificateChain()[0].toASN1Primitive().getEncoded(), encodedCert))
                    {
                        return alias;
                    }
                }
                catch (IOException e)
                {
                    // ignore - this should never happen
                }
            }
        }

        return null;
    }

    private byte[] generateKey(KeyDerivationFunc pbkdAlgorithm, String purpose, char[] password, int defKeySize)
        throws IOException
    {
        byte[] encPassword = PBEParametersGenerator.PKCS12PasswordToBytes(password);
        byte[] differentiator = PBEParametersGenerator.PKCS12PasswordToBytes(purpose.toCharArray());

        int keySizeInBytes = defKeySize;

        if (MiscObjectIdentifiers.id_scrypt.equals(pbkdAlgorithm.getAlgorithm()))
        {
            ScryptParams params = ScryptParams.getInstance(pbkdAlgorithm.getParameters());

            if (params.getKeyLength() != null)
            {
                keySizeInBytes = params.getKeyLength().intValue();
            }
            else if (keySizeInBytes == -1)
            {
                throw new IOException("no keyLength found in ScryptParams");
            }
            return SCrypt.generate(Arrays.concatenate(encPassword, differentiator), params.getSalt(),
                params.getCostParameter().intValue(), params.getBlockSize().intValue(),
                params.getBlockSize().intValue(), keySizeInBytes);
        }
        else if (pbkdAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBKDF2))
        {
            PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbkdAlgorithm.getParameters());

            if (pbkdf2Params.getKeyLength() != null)
            {
                keySizeInBytes = pbkdf2Params.getKeyLength().intValue();
            }
            else if (keySizeInBytes == -1)
            {
                throw new IOException("no keyLength found in PBKDF2Params");
            }

            if (pbkdf2Params.getPrf().getAlgorithm().equals(PKCSObjectIdentifiers.id_hmacWithSHA512))
            {
                PKCS5S2ParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA512Digest());

                pGen.init(Arrays.concatenate(encPassword, differentiator), pbkdf2Params.getSalt(), pbkdf2Params.getIterationCount().intValue());

                return ((KeyParameter)pGen.generateDerivedParameters(keySizeInBytes * 8)).getKey();
            }
            else if (pbkdf2Params.getPrf().getAlgorithm().equals(NISTObjectIdentifiers.id_hmacWithSHA3_512))
            {
                PKCS5S2ParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA3Digest(512));

                pGen.init(Arrays.concatenate(encPassword, differentiator), pbkdf2Params.getSalt(), pbkdf2Params.getIterationCount().intValue());

                return ((KeyParameter)pGen.generateDerivedParameters(keySizeInBytes * 8)).getKey();
            }
            else
            {
                throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD PRF: " + pbkdf2Params.getPrf().getAlgorithm());
            }
        }
        else
        {
            throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD.");
        }
    }

    private void verifyMac(byte[] content, PbkdMacIntegrityCheck integrityCheck, char[] password)
        throws NoSuchAlgorithmException, IOException
    {
        byte[] check = calculateMac(content, integrityCheck.getMacAlgorithm(), integrityCheck.getPbkdAlgorithm(), password);

        if (!Arrays.constantTimeAreEqual(check, integrityCheck.getMac()))
        {
            throw new IOException("BCFKS KeyStore corrupted: MAC calculation failed.");
        }
    }

    private byte[] calculateMac(byte[] content, AlgorithmIdentifier algorithm, KeyDerivationFunc pbkdAlgorithm, char[] password)
        throws NoSuchAlgorithmException, IOException
    {
        String algorithmId = algorithm.getAlgorithm().getId();

        Mac mac;
        if (provider != null)
        {
            mac = Mac.getInstance(algorithmId, provider);
        }
        else
        {
            mac = Mac.getInstance(algorithmId);
        }

        try
        {
            // no default key size for MAC.
            mac.init(new SecretKeySpec(generateKey(pbkdAlgorithm, "INTEGRITY_CHECK", ((password != null) ? password : new char[0]), -1), algorithmId));
        }
        catch (InvalidKeyException e)
        {
            throw new IOException("Cannot set up MAC calculation: " + e.getMessage());
        }

        return mac.doFinal(content);
    }

    public void engineStore(KeyStore.LoadStoreParameter parameter)
        throws CertificateException, NoSuchAlgorithmException, IOException
    {
        if (parameter == null)
        {
            throw new IllegalArgumentException("'parameter' arg cannot be null");
        }

        if (!(parameter instanceof BCFKSStoreParameter))
        {
            throw new IllegalArgumentException(
                "no support for 'parameter' of type " + parameter.getClass().getName());
        }

        BCFKSStoreParameter bcParam = (BCFKSStoreParameter)parameter;

        char[] password;
        KeyStore.ProtectionParameter protParam = bcParam.getProtectionParameter();
        if (protParam == null)
        {
            password = null;
        }
        else if (protParam instanceof KeyStore.PasswordProtection)
        {
            password = ((KeyStore.PasswordProtection)protParam).getPassword();
        }
        else if (protParam instanceof KeyStore.CallbackHandlerProtection)
        {
            CallbackHandler handler = ((KeyStore.CallbackHandlerProtection)protParam).getCallbackHandler();

            PasswordCallback passwordCallback = new PasswordCallback("password: ", false);

            try
            {
                handler.handle(new Callback[]{passwordCallback});

                password = passwordCallback.getPassword();
            }
            catch (UnsupportedCallbackException e)
            {
                throw new IllegalArgumentException("PasswordCallback not recognised: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new IllegalArgumentException(
                "no support for protection parameter of type " + protParam.getClass().getName());
        }

        if (bcParam.getStorePBKDFConfig().getAlgorithm().equals(MiscObjectIdentifiers.id_scrypt))
        {
            hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bcParam.getStorePBKDFConfig(), 512 / 8);
        }
        else
        {
            hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bcParam.getStorePBKDFConfig(), 512 / 8);
        }

        engineStore(bcParam.getOutputStream(), password);
    }

    public void engineStore(OutputStream outputStream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        ObjectData[] dataArray = (ObjectData[])entries.values().toArray(new ObjectData[entries.size()]);

        KeyDerivationFunc pbkdAlgId = generatePkbdAlgorithmIdentifier(hmacPkbdAlgorithm, 256 / 8);
        byte[] keyBytes = generateKey(pbkdAlgId, "STORE_ENCRYPTION", ((password != null) ? password : new char[0]), 256 / 8);

        ObjectStoreData storeData = new ObjectStoreData(hmacAlgorithm, creationDate, lastModifiedDate, new ObjectDataSequence(dataArray), null);
        EncryptedObjectStoreData encStoreData;

        try
        {
            Cipher c;
            if (provider == null)
            {
                c = Cipher.getInstance("AES/CCM/NoPadding");
            }
            else
            {
                c = Cipher.getInstance("AES/CCM/NoPadding", provider);
            }

            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));

            byte[] encOut = c.doFinal(storeData.getEncoded());

            AlgorithmParameters algorithmParameters = c.getParameters();

            PBES2Parameters pbeParams = new PBES2Parameters(pbkdAlgId, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters.getInstance(algorithmParameters.getEncoded())));

            encStoreData = new EncryptedObjectStoreData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pbeParams), encOut);
        }
        catch (NoSuchPaddingException e)
        {
            throw new NoSuchAlgorithmException(e.toString());
        }
        catch (BadPaddingException e)
        {
            throw new IOException(e.toString());
        }
        catch (IllegalBlockSizeException e)
        {
            throw new IOException(e.toString());
        }
        catch (InvalidKeyException e)
        {
            throw new IOException(e.toString());
        }

        // update the salt
        if (MiscObjectIdentifiers.id_scrypt.equals(hmacPkbdAlgorithm.getAlgorithm()))
        {
            ScryptParams sParams = ScryptParams.getInstance(hmacPkbdAlgorithm.getParameters());

            hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(hmacPkbdAlgorithm, sParams.getKeyLength().intValue());
        }
        else
        {
            PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(hmacPkbdAlgorithm.getParameters());

            hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(hmacPkbdAlgorithm, pbkdf2Params.getKeyLength().intValue());
        }
        byte[] mac = calculateMac(encStoreData.getEncoded(), hmacAlgorithm, hmacPkbdAlgorithm, password);

        ObjectStore store = new ObjectStore(encStoreData, new ObjectStoreIntegrityCheck(new PbkdMacIntegrityCheck(hmacAlgorithm, hmacPkbdAlgorithm, mac)));

        outputStream.write(store.getEncoded());

        outputStream.flush();
    }

    public void engineLoad(InputStream inputStream, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException
    {
        // reset any current values
        entries.clear();
        privateKeyCache.clear();

        lastModifiedDate = creationDate = null;
        hmacAlgorithm = null;

        if (inputStream == null)
        {
            // initialise defaults
            lastModifiedDate = creationDate = new Date();

            // basic initialisation
            hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
            hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, 512 / 8);

            return;
        }

        ASN1InputStream aIn = new ASN1InputStream(inputStream);

        ObjectStore store;

        try
        {
            store = ObjectStore.getInstance(aIn.readObject());
        }
        catch (Exception e)
        {
            throw new IOException(e.getMessage());
        }

        ObjectStoreIntegrityCheck integrityCheck = store.getIntegrityCheck();
        if (integrityCheck.getType() == ObjectStoreIntegrityCheck.PBKD_MAC_CHECK)
        {
            PbkdMacIntegrityCheck pbkdMacIntegrityCheck = PbkdMacIntegrityCheck.getInstance(integrityCheck.getIntegrityCheck());

            hmacAlgorithm = pbkdMacIntegrityCheck.getMacAlgorithm();
            hmacPkbdAlgorithm = pbkdMacIntegrityCheck.getPbkdAlgorithm();

            verifyMac(store.getStoreData().toASN1Primitive().getEncoded(), pbkdMacIntegrityCheck, password);
        }
        else
        {
            throw new IOException("BCFKS KeyStore unable to recognize integrity check.");
        }

        ASN1Encodable sData = store.getStoreData();

        ObjectStoreData storeData;
        if (sData instanceof EncryptedObjectStoreData)
        {
            EncryptedObjectStoreData encryptedStoreData = (EncryptedObjectStoreData)sData;
            AlgorithmIdentifier protectAlgId = encryptedStoreData.getEncryptionAlgorithm();

            storeData = ObjectStoreData.getInstance(decryptData("STORE_ENCRYPTION", protectAlgId, password, encryptedStoreData.getEncryptedContent().getOctets()));
        }
        else
        {
            storeData = ObjectStoreData.getInstance(sData);
        }

        try
        {
            creationDate = storeData.getCreationDate().getDate();
            lastModifiedDate = storeData.getLastModifiedDate().getDate();
        }
        catch (ParseException e)
        {
            throw new IOException("BCFKS KeyStore unable to parse store data information.");
        }

        if (!storeData.getIntegrityAlgorithm().equals(hmacAlgorithm))
        {
            throw new IOException("BCFKS KeyStore storeData integrity algorithm does not match store integrity algorithm.");
        }

        for (Iterator it = storeData.getObjectDataSequence().iterator(); it.hasNext(); )
        {
            ObjectData objData = ObjectData.getInstance(it.next());

            entries.put(objData.getIdentifier(), objData);
        }
    }

    private byte[] decryptData(String purpose, AlgorithmIdentifier protectAlgId, char[] password, byte[] encryptedData)
        throws IOException
    {
        if (!protectAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBES2))
        {
            throw new IOException("BCFKS KeyStore cannot recognize protection algorithm.");
        }

        PBES2Parameters pbes2Parameters = PBES2Parameters.getInstance(protectAlgId.getParameters());
        EncryptionScheme algId = pbes2Parameters.getEncryptionScheme();

        try
        {
            Cipher c;
            AlgorithmParameters algParams;
            if (algId.getAlgorithm().equals(NISTObjectIdentifiers.id_aes256_CCM))
            {
                if (provider == null)
                {
                    c = Cipher.getInstance("AES/CCM/NoPadding");
                    algParams = AlgorithmParameters.getInstance("CCM");
                }
                else
                {
                    c = Cipher.getInstance("AES/CCM/NoPadding", provider);
                    algParams = AlgorithmParameters.getInstance("CCM", provider);
                }

                CCMParameters ccmParameters = CCMParameters.getInstance(algId.getParameters());

                algParams.init(ccmParameters.getEncoded());
            }
            else if (algId.getAlgorithm().equals(NISTObjectIdentifiers.id_aes256_wrap_pad))
            {
                if (provider == null)
                {
                    c = Cipher.getInstance("AESKWP");
                    algParams = null;
                }
                else
                {
                    c = Cipher.getInstance("AESKWP", provider);
                    algParams = null;
                }
            }
            else
            {
                throw new IOException("BCFKS KeyStore cannot recognize protection encryption algorithm.");
            }

            byte[] keyBytes = generateKey(pbes2Parameters.getKeyDerivationFunc(), purpose, ((password != null) ? password : new char[0]), 32);

            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), algParams);

            byte[] rv = c.doFinal(encryptedData);
            return rv;
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new IOException(e.toString());
        }
    }

    private KeyDerivationFunc generatePkbdAlgorithmIdentifier(PBKDFConfig pbkdfConfig, int keySizeInBytes)
    {
        if (MiscObjectIdentifiers.id_scrypt.equals(pbkdfConfig.getAlgorithm()))
        {
            ScryptConfig scryptConfig = (ScryptConfig)pbkdfConfig;

            byte[] pbkdSalt = new byte[scryptConfig.getSaltLength()];
            getDefaultSecureRandom().nextBytes(pbkdSalt);

            ScryptParams params = new ScryptParams(
                pbkdSalt,
                scryptConfig.getCostParameter(), scryptConfig.getBlockSize(), scryptConfig.getParallelizationParameter(), keySizeInBytes);

            return new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt, params);
        }
        else
        {
            PBKDF2Config pbkdf2Config = (PBKDF2Config)pbkdfConfig;

            byte[] pbkdSalt = new byte[pbkdf2Config.getSaltLength()];
            getDefaultSecureRandom().nextBytes(pbkdSalt);

            return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(pbkdSalt, pbkdf2Config.getIterationCount(), keySizeInBytes, pbkdf2Config.getPRF()));
        }
    }

    private KeyDerivationFunc generatePkbdAlgorithmIdentifier(KeyDerivationFunc baseAlg, int keySizeInBytes)
    {
        if (MiscObjectIdentifiers.id_scrypt.equals(baseAlg.getAlgorithm()))
        {
            ScryptParams oldParams = ScryptParams.getInstance(baseAlg.getParameters());

            byte[] pbkdSalt = new byte[oldParams.getSalt().length];
            getDefaultSecureRandom().nextBytes(pbkdSalt);

            ScryptParams params = new ScryptParams(
                pbkdSalt,
                oldParams.getCostParameter(), oldParams.getBlockSize(), oldParams.getParallelizationParameter(), BigInteger.valueOf(keySizeInBytes));

            return new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt, params);
        }
        else
        {
            PBKDF2Params oldParams = PBKDF2Params.getInstance(baseAlg.getParameters());
  
            byte[] pbkdSalt = new byte[oldParams.getSalt().length];
            getDefaultSecureRandom().nextBytes(pbkdSalt);

            PBKDF2Params params = new PBKDF2Params(pbkdSalt,
                oldParams.getIterationCount().intValue(), keySizeInBytes, oldParams.getPrf());
            return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, params);
        }
    }

    private KeyDerivationFunc generatePkbdAlgorithmIdentifier(ASN1ObjectIdentifier derivationAlgorithm, int keySizeInBytes)
    {
        byte[] pbkdSalt = new byte[512 / 8];
        getDefaultSecureRandom().nextBytes(pbkdSalt);

        if (PKCSObjectIdentifiers.id_PBKDF2.equals(derivationAlgorithm))
        {
            return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(pbkdSalt, 50 * 1024, keySizeInBytes, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE)));
        }
        else
        {
            throw new IllegalStateException("unknown derivation algorithm: " + derivationAlgorithm);
        }
    }

    public static class Std
        extends BcFKSKeyStoreSpi
    {
        public Std()
        {
            super(new BouncyCastleProvider());
        }
    }

    public static class Def
        extends BcFKSKeyStoreSpi
    {
        public Def()
        {
            super(null);
        }
    }

    private static class SharedKeyStoreSpi
        extends BcFKSKeyStoreSpi
        implements PKCSObjectIdentifiers, X509ObjectIdentifiers
    {
        private final Map<String, byte[]> cache;
        private final byte[] seedKey;

        public SharedKeyStoreSpi(BouncyCastleProvider provider)
        {
            super(provider);

            try
            {
                this.seedKey = new byte[32];

                if (provider != null)
                {
                    SecureRandom.getInstance("DEFAULT", provider).nextBytes(seedKey);
                }
                else
                {
                    SecureRandom.getInstance("DEFAULT").nextBytes(seedKey);
                }
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new IllegalArgumentException("can't create cert factory - " + e.toString());
            }

            this.cache = new HashMap<String, byte[]>();
        }

        public void engineDeleteEntry(
            String alias)
            throws KeyStoreException
        {
            cache.remove(alias);
            super.engineDeleteEntry(alias);
        }

        public Key engineGetKey(
            String alias,
            char[] password)
            throws NoSuchAlgorithmException, UnrecoverableKeyException
        {
            byte[] mac;

            try
            {
                mac = calculateMac(alias, password);
            }
            catch (InvalidKeyException e)
            {   // this should never happen...
                throw new UnrecoverableKeyException("unable to recover key (" + alias + "): " + e.getMessage());
            }

            if (cache.containsKey(alias))
            {
                byte[] hash = cache.get(alias);

                if (!Arrays.constantTimeAreEqual(hash, mac))
                {
                    throw new UnrecoverableKeyException("unable to recover key (" + alias + ")");
                }
            }

            Key key = super.engineGetKey(alias, password);

            if (key != null && !cache.containsKey(alias))
            {
                cache.put(alias, mac);
            }

            return key;
        }

        private byte[] calculateMac(String alias, char[] password)
            throws NoSuchAlgorithmException, InvalidKeyException
        {
            byte[] encoding;
            if (password != null)
            {
                encoding = Arrays.concatenate(Strings.toUTF8ByteArray(password), Strings.toUTF8ByteArray(alias));
            }
            else
            {
                encoding = Arrays.concatenate(seedKey, Strings.toUTF8ByteArray(alias));
            }

            return SCrypt.generate(encoding, seedKey, 16384, 8, 1, 32);
        }
    }

    public static class StdShared
        extends SharedKeyStoreSpi
    {
        public StdShared()
        {
            super(new BouncyCastleProvider());
        }
    }

    public static class DefShared
        extends SharedKeyStoreSpi
    {
        public DefShared()
        {
            super(null);
        }
    }

    private static class ExtKeyStoreException
        extends KeyStoreException
    {
        private final Throwable cause;

        ExtKeyStoreException(String msg, Throwable cause)
        {
            super(msg);
            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }
}
