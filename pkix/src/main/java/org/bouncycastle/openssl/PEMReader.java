package org.bouncycastle.openssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectParser;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V2AttributeCertificate;

/**
 * Class for reading OpenSSL PEM encoded streams containing
 * X509 certificates, PKCS8 encoded keys and PKCS7 objects.
 * <p>
 * In the case of PKCS7 objects the reader will return a CMS ContentInfo object. Keys and
 * Certificates will be returned using the appropriate java.security type (KeyPair, PublicKey, X509Certificate,
 * or X509CRL). In the case of a Certificate Request a PKCS10CertificationRequest will be returned.
 * </p>
 *
 * @deprecated use PEMParser
 */
public class PEMReader
    extends PemReader
{
    private final Map parsers = new HashMap();

    private PasswordFinder pFinder;


    /**
     * Create a new PEMReader
     *
     * @param reader the Reader
     * @deprecated use PEMParser
     */
    public PEMReader(
        Reader reader)
    {
        this(reader, null, "BC");
    }

    /**
     * Create a new PEMReader with a password finder
     *
     * @param reader  the Reader
     * @param pFinder the password finder
     * @deprecated use PEMParser
     */
    public PEMReader(
        Reader reader,
        PasswordFinder pFinder)
    {
        this(reader, pFinder, "BC");
    }

    /**
     * Create a new PEMReader with a password finder
     *
     * @param reader   the Reader
     * @param pFinder  the password finder
     * @param provider the cryptography provider to use
     * @deprecated use PEMParser
     */
    public PEMReader(
        Reader reader,
        PasswordFinder pFinder,
        String provider)
    {
        this(reader, pFinder, provider, provider);
    }

    /**
     * Create a new PEMReader with a password finder and differing providers for secret and public key
     * operations.
     *
     * @param reader       the Reader
     * @param pFinder      the password finder
     * @param symProvider  provider to use for symmetric operations
     * @param asymProvider provider to use for asymmetric (public/private key) operations
     * @deprecated use PEMParser
     */
    public PEMReader(
        Reader reader,
        PasswordFinder pFinder,
        String symProvider,
        String asymProvider)
    {
        super(reader);

        this.pFinder = pFinder;

        parsers.put("CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
        parsers.put("NEW CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
        parsers.put("CERTIFICATE", new X509CertificateParser(asymProvider));
        parsers.put("X509 CERTIFICATE", new X509CertificateParser(asymProvider));
        parsers.put("X509 CRL", new X509CRLParser(asymProvider));
        parsers.put("PKCS7", new PKCS7Parser());
        parsers.put("ATTRIBUTE CERTIFICATE", new X509AttributeCertificateParser());
        parsers.put("EC PARAMETERS", new ECNamedCurveSpecParser());
        parsers.put("PUBLIC KEY", new PublicKeyParser(asymProvider));
        parsers.put("RSA PUBLIC KEY", new RSAPublicKeyParser(asymProvider));
        parsers.put("RSA PRIVATE KEY", new RSAKeyPairParser(symProvider, asymProvider));
        parsers.put("DSA PRIVATE KEY", new DSAKeyPairParser(symProvider, asymProvider));
        parsers.put("EC PRIVATE KEY", new ECDSAKeyPairParser(symProvider, asymProvider));
        parsers.put("ENCRYPTED PRIVATE KEY", new EncryptedPrivateKeyParser(symProvider, asymProvider));
        parsers.put("PRIVATE KEY", new PrivateKeyParser(asymProvider));
    }

    public Object readObject()
        throws IOException
    {
        PemObject obj = readPemObject();

        if (obj != null)
        {
            String type = obj.getType();
            if (parsers.containsKey(type))
            {
                return ((PemObjectParser)parsers.get(type)).parseObject(obj);
            }
            else
            {
                throw new IOException("unrecognised object: " + type);
            }
        }

        return null;
    }

    private abstract class KeyPairParser
        implements PemObjectParser
    {
        protected String symProvider;

        public KeyPairParser(String symProvider)
        {
            this.symProvider = symProvider;
        }

        /**
         * Read a Key Pair
         */
        protected ASN1Sequence readKeyPair(
            PemObject obj)
            throws IOException
        {
            boolean isEncrypted = false;
            String dekInfo = null;
            List headers = obj.getHeaders();

            for (Iterator it = headers.iterator(); it.hasNext(); )
            {
                PemHeader hdr = (PemHeader)it.next();

                if (hdr.getName().equals("Proc-Type") && hdr.getValue().equals("4,ENCRYPTED"))
                {
                    isEncrypted = true;
                }
                else if (hdr.getName().equals("DEK-Info"))
                {
                    dekInfo = hdr.getValue();
                }
            }

            //
            // extract the key
            //
            byte[] keyBytes = obj.getContent();

            if (isEncrypted)
            {
                if (pFinder == null)
                {
                    throw new PasswordException("No password finder specified, but a password is required");
                }

                char[] password = pFinder.getPassword();

                if (password == null)
                {
                    throw new PasswordException("Password is null, but a password is required");
                }

                StringTokenizer tknz = new StringTokenizer(dekInfo, ",");
                String dekAlgName = tknz.nextToken();
                byte[] iv = Hex.decode(tknz.nextToken());

                keyBytes = crypt(false, symProvider, keyBytes, password, dekAlgName, iv);
            }

            try
            {
                return ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(keyBytes));
            }
            catch (IOException e)
            {
                if (isEncrypted)
                {
                    throw new PEMException("exception decoding - please check password and data.", e);
                }
                else
                {
                    throw new PEMException(e.getMessage(), e);
                }
            }
            catch (IllegalArgumentException e)
            {
                if (isEncrypted)
                {
                    throw new PEMException("exception decoding - please check password and data.", e);
                }
                else
                {
                    throw new PEMException(e.getMessage(), e);
                }
            }
        }
    }

    private class DSAKeyPairParser
        extends KeyPairParser
    {
        private String asymProvider;

        public DSAKeyPairParser(String symProvider, String asymProvider)
        {
            super(symProvider);

            this.asymProvider = asymProvider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1Sequence seq = readKeyPair(obj);

                if (seq.size() != 6)
                {
                    throw new PEMException("malformed sequence in DSA private key");
                }

                //            DERInteger              v = (DERInteger)seq.getObjectAt(0);
                DERInteger p = (DERInteger)seq.getObjectAt(1);
                DERInteger q = (DERInteger)seq.getObjectAt(2);
                DERInteger g = (DERInteger)seq.getObjectAt(3);
                DERInteger y = (DERInteger)seq.getObjectAt(4);
                DERInteger x = (DERInteger)seq.getObjectAt(5);

                DSAPrivateKeySpec privSpec = new DSAPrivateKeySpec(
                    x.getValue(), p.getValue(),
                    q.getValue(), g.getValue());
                DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(
                    y.getValue(), p.getValue(),
                    q.getValue(), g.getValue());

                KeyFactory fact = KeyFactory.getInstance("DSA", asymProvider);

                return new KeyPair(
                    fact.generatePublic(pubSpec),
                    fact.generatePrivate(privSpec));
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating DSA private key: " + e.toString(), e);
            }
        }
    }

    private class ECDSAKeyPairParser
        extends KeyPairParser
    {
        private String asymProvider;

        public ECDSAKeyPairParser(String symProvider, String asymProvider)
        {
            super(symProvider);

            this.asymProvider = asymProvider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1Sequence seq = readKeyPair(obj);

                org.bouncycastle.asn1.sec.ECPrivateKey pKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(seq);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
                PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
                SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pKey.getPublicKey().getBytes());

                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privInfo.getEncoded());
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());


                KeyFactory fact = KeyFactory.getInstance("ECDSA", asymProvider);


                return new KeyPair(
                    fact.generatePublic(pubSpec),
                    fact.generatePrivate(privSpec));
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating EC private key: " + e.toString(), e);
            }
        }
    }

    private class RSAKeyPairParser
        extends KeyPairParser
    {
        private String asymProvider;

        public RSAKeyPairParser(String symProvider, String asymProvider)
        {
            super(symProvider);

            this.asymProvider = asymProvider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1Sequence seq = readKeyPair(obj);

                if (seq.size() != 9)
                {
                    throw new PEMException("malformed sequence in RSA private key");
                }

                org.bouncycastle.asn1.pkcs.RSAPrivateKey keyStruct = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq);

                RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(
                    keyStruct.getModulus(), keyStruct.getPublicExponent());
                RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(
                    keyStruct.getModulus(), keyStruct.getPublicExponent(), keyStruct.getPrivateExponent(),
                    keyStruct.getPrime1(), keyStruct.getPrime2(),
                    keyStruct.getExponent1(), keyStruct.getExponent2(),
                    keyStruct.getCoefficient());

                KeyFactory fact = KeyFactory.getInstance("RSA", asymProvider);

                return new KeyPair(
                    fact.generatePublic(pubSpec),
                    fact.generatePrivate(privSpec));
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating RSA private key: " + e.toString(), e);
            }
        }
    }

    private class PublicKeyParser
        implements PemObjectParser
    {
        private String provider;

        public PublicKeyParser(String provider)
        {
            this.provider = provider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            KeySpec keySpec = new X509EncodedKeySpec(obj.getContent());
            String[] algorithms = {"DSA", "RSA"};
            for (int i = 0; i < algorithms.length; i++)
            {
                try
                {
                    KeyFactory keyFact = KeyFactory.getInstance(algorithms[i], provider);
                    PublicKey pubKey = keyFact.generatePublic(keySpec);

                    return pubKey;
                }
                catch (NoSuchAlgorithmException e)
                {
                    // ignore
                }
                catch (InvalidKeySpecException e)
                {
                    // ignore
                }
                catch (NoSuchProviderException e)
                {
                    throw new RuntimeException("can't find provider " + provider);
                }
            }

            return null;
        }
    }

    private class RSAPublicKeyParser
        implements PemObjectParser
    {
        private String provider;

        public RSAPublicKeyParser(String provider)
        {
            this.provider = provider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1InputStream ais = new ASN1InputStream(obj.getContent());
                Object asnObject = ais.readObject();
                ASN1Sequence sequence = (ASN1Sequence)asnObject;
                RSAPublicKey rsaPubStructure = RSAPublicKey.getInstance(sequence);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
                    rsaPubStructure.getModulus(),
                    rsaPubStructure.getPublicExponent());


                KeyFactory keyFact = KeyFactory.getInstance("RSA", provider);

                return keyFact.generatePublic(keySpec);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (NoSuchProviderException e)
            {
                throw new IOException("can't find provider " + provider);
            }
            catch (Exception e)
            {
                throw new PEMException("problem extracting key: " + e.toString(), e);
            }
        }
    }

    private class X509CertificateParser
        implements PemObjectParser
    {
        private String provider;

        public X509CertificateParser(String provider)
        {
            this.provider = provider;
        }

        /**
         * Reads in a X509Certificate.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            ByteArrayInputStream bIn = new ByteArrayInputStream(obj.getContent());

            try
            {
                CertificateFactory certFact
                    = CertificateFactory.getInstance("X.509", provider);

                return certFact.generateCertificate(bIn);
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class X509CRLParser
        implements PemObjectParser
    {
        private String provider;

        public X509CRLParser(String provider)
        {
            this.provider = provider;
        }

        /**
         * Reads in a X509CRL.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            ByteArrayInputStream bIn = new ByteArrayInputStream(obj.getContent());

            try
            {
                CertificateFactory certFact
                    = CertificateFactory.getInstance("X.509", provider);

                return certFact.generateCRL(bIn);
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class PKCS10CertificationRequestParser
        implements PemObjectParser
    {
        /**
         * Reads in a PKCS10 certification request.
         *
         * @return the certificate request.
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new PKCS10CertificationRequest(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing certrequest: " + e.toString(), e);
            }
        }
    }

    private class PKCS7Parser
        implements PemObjectParser
    {
        /**
         * Reads in a PKCS7 object. This returns a ContentInfo object suitable for use with the CMS
         * API.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1InputStream aIn = new ASN1InputStream(obj.getContent());

                return ContentInfo.getInstance(aIn.readObject());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing PKCS7 object: " + e.toString(), e);
            }
        }
    }

    private class X509AttributeCertificateParser
        implements PemObjectParser
    {
        public Object parseObject(PemObject obj)
            throws IOException
        {
            return new X509V2AttributeCertificate(obj.getContent());
        }
    }

    private class ECNamedCurveSpecParser
        implements PemObjectParser
    {
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                DERObjectIdentifier oid = (DERObjectIdentifier)ASN1Primitive.fromByteArray(obj.getContent());

                Object params = ECNamedCurveTable.getParameterSpec(oid.getId());

                if (params == null)
                {
                    throw new IOException("object ID not found in EC curve table");
                }

                return params;
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException("exception extracting EC named curve: " + e.toString());
            }
        }
    }

    private class EncryptedPrivateKeyParser
        implements PemObjectParser
    {
        private String symProvider;
        private String asymProvider;

        public EncryptedPrivateKeyParser(String symProvider, String asymProvider)
        {
            this.symProvider = symProvider;
            this.asymProvider = asymProvider;
        }

        /**
         * Reads in a X509CRL.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                EncryptedPrivateKeyInfo info = EncryptedPrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(obj.getContent()));
                AlgorithmIdentifier algId = info.getEncryptionAlgorithm();

                if (pFinder == null)
                {
                    throw new PEMException("no PasswordFinder specified");
                }

                if (PEMUtilities.isPKCS5Scheme2(algId.getAlgorithm()))
                {
                    PBES2Parameters params = PBES2Parameters.getInstance(algId.getParameters());
                    KeyDerivationFunc func = params.getKeyDerivationFunc();
                    EncryptionScheme scheme = params.getEncryptionScheme();
                    PBKDF2Params defParams = (PBKDF2Params)func.getParameters();

                    int iterationCount = defParams.getIterationCount().intValue();
                    byte[] salt = defParams.getSalt();

                    String algorithm = scheme.getAlgorithm().getId();

                    SecretKey key = generateSecretKeyForPKCS5Scheme2(algorithm, pFinder.getPassword(), salt, iterationCount);

                    Cipher cipher = Cipher.getInstance(algorithm, symProvider);
                    AlgorithmParameters algParams = AlgorithmParameters.getInstance(algorithm, symProvider);

                    algParams.init(scheme.getParameters().toASN1Primitive().getEncoded());

                    cipher.init(Cipher.DECRYPT_MODE, key, algParams);

                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(cipher.doFinal(info.getEncryptedData())));
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pInfo.getEncoded());

                    KeyFactory keyFact = KeyFactory.getInstance(pInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), asymProvider);

                    return keyFact.generatePrivate(keySpec);
                }
                else if (PEMUtilities.isPKCS12(algId.getAlgorithm()))
                {
                    PKCS12PBEParams params = PKCS12PBEParams.getInstance(algId.getParameters());
                    String algorithm = algId.getAlgorithm().getId();
                    PBEKeySpec pbeSpec = new PBEKeySpec(pFinder.getPassword());

                    SecretKeyFactory secKeyFact = SecretKeyFactory.getInstance(algorithm, symProvider);
                    PBEParameterSpec defParams = new PBEParameterSpec(params.getIV(), params.getIterations().intValue());

                    Cipher cipher = Cipher.getInstance(algorithm, symProvider);

                    cipher.init(Cipher.DECRYPT_MODE, secKeyFact.generateSecret(pbeSpec), defParams);

                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(cipher.doFinal(info.getEncryptedData())));
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pInfo.getEncoded());

                    KeyFactory keyFact = KeyFactory.getInstance(pInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), asymProvider);

                    return keyFact.generatePrivate(keySpec);
                }
                else if (PEMUtilities.isPKCS5Scheme1(algId.getAlgorithm()))
                {
                    PBEParameter params = PBEParameter.getInstance(algId.getParameters());
                    String algorithm = algId.getAlgorithm().getId();
                    PBEKeySpec pbeSpec = new PBEKeySpec(pFinder.getPassword());

                    SecretKeyFactory secKeyFact = SecretKeyFactory.getInstance(algorithm, symProvider);
                    PBEParameterSpec defParams = new PBEParameterSpec(params.getSalt(), params.getIterationCount().intValue());

                    Cipher cipher = Cipher.getInstance(algorithm, symProvider);

                    cipher.init(Cipher.DECRYPT_MODE, secKeyFact.generateSecret(pbeSpec), defParams);

                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(cipher.doFinal(info.getEncryptedData())));
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pInfo.getEncoded());

                    KeyFactory keyFact = KeyFactory.getInstance(pInfo.getPrivateKeyAlgorithm().getAlgorithm().getId(), asymProvider);

                    return keyFact.generatePrivate(keySpec);
                }
                else
                {
                    throw new PEMException("Unknown algorithm: " + algId.getAlgorithm());
                }
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing ENCRYPTED PRIVATE KEY: " + e.toString(), e);
            }
        }
    }

    private class PrivateKeyParser
        implements PemObjectParser
    {
        private String provider;

        public PrivateKeyParser(String provider)
        {
            this.provider = provider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(obj.getContent()));
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(obj.getContent());

                KeyFactory keyFact = KeyFactory.getInstance(info.getPrivateKeyAlgorithm().getAlgorithm().getId(), provider);

                return keyFact.generatePrivate(keySpec);
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing PRIVATE KEY: " + e.toString(), e);
            }
        }
    }

    static byte[] crypt(
        boolean encrypt,
        String provider,
        byte[] bytes,
        char[] password,
        String dekAlgName,
        byte[] iv)
        throws IOException
    {
        Provider prov = null;
        if (provider != null)
        {
            prov = Security.getProvider(provider);
            if (prov == null)
            {
                throw new EncryptionException("cannot find provider: " + provider);
            }
        }

        return crypt(encrypt, prov, bytes, password, dekAlgName, iv);
    }

    static byte[] crypt(
        boolean encrypt,
        Provider provider,
        byte[] bytes,
        char[] password,
        String dekAlgName,
        byte[] iv)
        throws IOException
    {
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        String alg;
        String blockMode = "CBC";
        String padding = "PKCS5Padding";
        Key sKey;

        // Figure out block mode and padding.
        if (dekAlgName.endsWith("-CFB"))
        {
            blockMode = "CFB";
            padding = "NoPadding";
        }
        if (dekAlgName.endsWith("-ECB") ||
            "DES-EDE".equals(dekAlgName) ||
            "DES-EDE3".equals(dekAlgName))
        {
            // ECB is actually the default (though seldom used) when OpenSSL
            // uses DES-EDE (des2) or DES-EDE3 (des3).
            blockMode = "ECB";
            paramSpec = null;
        }
        if (dekAlgName.endsWith("-OFB"))
        {
            blockMode = "OFB";
            padding = "NoPadding";
        }


        // Figure out algorithm and key size.
        if (dekAlgName.startsWith("DES-EDE"))
        {
            alg = "DESede";
            // "DES-EDE" is actually des2 in OpenSSL-speak!
            // "DES-EDE3" is des3.
            boolean des2 = !dekAlgName.startsWith("DES-EDE3");
            sKey = getKey(password, alg, 24, iv, des2);
        }
        else if (dekAlgName.startsWith("DES-"))
        {
            alg = "DES";
            sKey = getKey(password, alg, 8, iv);
        }
        else if (dekAlgName.startsWith("BF-"))
        {
            alg = "Blowfish";
            sKey = getKey(password, alg, 16, iv);
        }
        else if (dekAlgName.startsWith("RC2-"))
        {
            alg = "RC2";
            int keyBits = 128;
            if (dekAlgName.startsWith("RC2-40-"))
            {
                keyBits = 40;
            }
            else if (dekAlgName.startsWith("RC2-64-"))
            {
                keyBits = 64;
            }
            sKey = getKey(password, alg, keyBits / 8, iv);
            if (paramSpec == null) // ECB block mode
            {
                paramSpec = new RC2ParameterSpec(keyBits);
            }
            else
            {
                paramSpec = new RC2ParameterSpec(keyBits, iv);
            }
        }
        else if (dekAlgName.startsWith("AES-"))
        {
            alg = "AES";
            byte[] salt = iv;
            if (salt.length > 8)
            {
                salt = new byte[8];
                System.arraycopy(iv, 0, salt, 0, 8);
            }

            int keyBits;
            if (dekAlgName.startsWith("AES-128-"))
            {
                keyBits = 128;
            }
            else if (dekAlgName.startsWith("AES-192-"))
            {
                keyBits = 192;
            }
            else if (dekAlgName.startsWith("AES-256-"))
            {
                keyBits = 256;
            }
            else
            {
                throw new EncryptionException("unknown AES encryption with private key");
            }
            sKey = getKey(password, "AES", keyBits / 8, salt);
        }
        else
        {
            throw new EncryptionException("unknown encryption with private key");
        }

        String transformation = alg + "/" + blockMode + "/" + padding;

        try
        {
            Cipher c = Cipher.getInstance(transformation, provider);
            int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

            if (paramSpec == null) // ECB block mode
            {
                c.init(mode, sKey);
            }
            else
            {
                c.init(mode, sKey, paramSpec);
            }
            return c.doFinal(bytes);
        }
        catch (Exception e)
        {
            throw new EncryptionException("exception using cipher - please check password and data.", e);
        }
    }

    private static SecretKey getKey(
        char[] password,
        String algorithm,
        int keyLength,
        byte[] salt)
    {
        return getKey(password, algorithm, keyLength, salt, false);
    }

    private static SecretKey getKey(
        char[] password,
        String algorithm,
        int keyLength,
        byte[] salt,
        boolean des2)
    {
        OpenSSLPBEParametersGenerator pGen = new OpenSSLPBEParametersGenerator();

        pGen.init(PBEParametersGenerator.PKCS5PasswordToBytes(password), salt);

        KeyParameter keyParam;
        keyParam = (KeyParameter)pGen.generateDerivedParameters(keyLength * 8);
        byte[] key = keyParam.getKey();
        if (des2 && key.length >= 24)
        {
            // For DES2, we must copy first 8 bytes into the last 8 bytes.
            System.arraycopy(key, 0, key, 16, 8);
        }
        return new javax.crypto.spec.SecretKeySpec(key, algorithm);
    }


    public static SecretKey generateSecretKeyForPKCS5Scheme2(String algorithm, char[] password, byte[] salt, int iterationCount)
    {
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();

        generator.init(
            PBEParametersGenerator.PKCS5PasswordToBytes(password),
            salt,
            iterationCount);

        return new SecretKeySpec(((KeyParameter)generator.generateDerivedParameters(PEMUtilities.getKeySize(algorithm))).getKey(), algorithm);
    }
}
