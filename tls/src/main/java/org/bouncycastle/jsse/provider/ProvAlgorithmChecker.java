package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.util.Arrays;

class ProvAlgorithmChecker
    extends PKIXCertPathChecker
{
    static final int KU_DIGITAL_SIGNATURE = 0;
    static final int KU_KEY_ENCIPHERMENT = 2;
    static final int KU_KEY_AGREEMENT = 4;

    private static final Map<String, String> sigAlgNames = createSigAlgNames();
    private static final Set<String> sigAlgNoParams = createSigAlgNoParams();

    private static final byte[] DER_NULL_ENCODING = new byte[]{ 0x05, 0x00 };

    private static final String SIG_ALG_NAME_rsa_pss_pss_sha256 = JsseUtils
        .getJcaSignatureAlgorithmBC("SHA256withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha384 = JsseUtils
        .getJcaSignatureAlgorithmBC("SHA384withRSAandMGF1", "RSASSA-PSS");
    private static final String SIG_ALG_NAME_rsa_pss_pss_sha512 = JsseUtils
        .getJcaSignatureAlgorithmBC("SHA512withRSAandMGF1", "RSASSA-PSS");

    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha256 = JsseUtils
        .getJcaSignatureAlgorithmBC("SHA256withRSAandMGF1", "RSA");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha384 = JsseUtils
        .getJcaSignatureAlgorithmBC("SHA384withRSAandMGF1", "RSA");
    private static final String SIG_ALG_NAME_rsa_pss_rsae_sha512 = JsseUtils
        .getJcaSignatureAlgorithmBC("SHA512withRSAandMGF1", "RSA");

    private static Map<String, String> createSigAlgNames()
    {
        Map<String, String> names = new HashMap<String, String>(4);

        names.put(EdECObjectIdentifiers.id_Ed25519.getId(), "Ed25519");
        names.put(EdECObjectIdentifiers.id_Ed448.getId(), "Ed448");
        names.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "SHA1withDSA");
        names.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "SHA1withDSA");

        return Collections.unmodifiableMap(names);
    }

    private static Set<String> createSigAlgNoParams()
    {
        Set<String> noParams = new HashSet<String>();

        noParams.add(OIWObjectIdentifiers.dsaWithSHA1.getId());
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1.getId());
        noParams.add(PKCSObjectIdentifiers.id_RSASSA_PSS.getId());

        return Collections.unmodifiableSet(noParams);
    }

    @SuppressWarnings("unused")
    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final BCAlgorithmConstraints algorithmConstraints;

    private X509Certificate issuerCert;

    ProvAlgorithmChecker(boolean isInFipsMode, JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints)
    {
        if (null == helper)
        {
            throw new NullPointerException("'helper' cannot be null");
        }
        if (null == algorithmConstraints)
        {
            throw new NullPointerException("'algorithmConstraints' cannot be null");
        }

        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.algorithmConstraints = algorithmConstraints;

        this.issuerCert = null;
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException
    {
        if (forward)
        {
            throw new CertPathValidatorException("forward checking not supported");
        }

        this.issuerCert = null;
    }

    @Override
    public boolean isForwardCheckingSupported()
    {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions()
    {
        return null;
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException
    {
        if (!(cert instanceof X509Certificate))
        {
            throw new CertPathValidatorException("checker can only be used for X.509 certificates");
        }

        X509Certificate subjectCert = (X509Certificate)cert;

        if (isInFipsMode && !isValidFIPSPublicKey(subjectCert.getPublicKey()))
        {
            throw new CertPathValidatorException("non-FIPS public key found");
        }

        if (null == issuerCert)
        {
            // NOTE: This would be redundant with the 'taCert' check in 'checkCertPathExtras'
            //checkIssued(helper, algorithmConstraints, subjectCert);
        }
        else
        {
            checkIssuedBy(helper, algorithmConstraints, subjectCert, issuerCert);
        }

        this.issuerCert = subjectCert;
    }

    static void checkCertPathExtras(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate[] chain, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException
    {
        X509Certificate taCert = chain[chain.length - 1];

        if (chain.length > 1)
        {
            checkIssuedBy(helper, algorithmConstraints, chain[chain.length - 2], taCert);
        }

        X509Certificate eeCert = chain[0];

        checkEndEntity(helper, algorithmConstraints, eeCert, ekuOID, kuBit);
    }

    static void checkChain(boolean isInFipsMode, JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        Set<X509Certificate> trustedCerts, X509Certificate[] chain, KeyPurposeId ekuOID, int kuBit)
        throws CertPathValidatorException
    {
        int taPos = chain.length;
        while (taPos > 0 && trustedCerts.contains(chain[taPos - 1]))
        {
            --taPos;
        }

        if (taPos < chain.length)
        {
            X509Certificate taCert = chain[taPos];

            if (taPos > 0)
            {
                checkIssuedBy(helper, algorithmConstraints, chain[taPos - 1], taCert);
            }
        }
        else
        {
            checkIssued(helper, algorithmConstraints, chain[taPos - 1]);
        }

        ProvAlgorithmChecker algorithmChecker = new ProvAlgorithmChecker(isInFipsMode, helper, algorithmConstraints);
        algorithmChecker.init(false);

        for (int i = taPos - 1; i >= 0; --i)
        {
            algorithmChecker.check(chain[i], Collections.<String> emptySet());
        }

        X509Certificate eeCert = chain[0];

        checkEndEntity(helper, algorithmConstraints, eeCert, ekuOID, kuBit);
    }

    private static void checkEndEntity(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate eeCert, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException
    {
        if (null != ekuOID)
        {
            if (!supportsExtendedKeyUsage(eeCert, ekuOID))
            {
                throw new CertPathValidatorException(
                    "Certificate doesn't support '" + getExtendedKeyUsageName(ekuOID) + "' ExtendedKeyUsage");
            }
        }

        if (kuBit >= 0)
        {
            if (!supportsKeyUsage(eeCert, kuBit))
            {
                throw new CertPathValidatorException(
                    "Certificate doesn't support '" + getKeyUsageName(kuBit) + "' KeyUsage");
            }

            if (!algorithmConstraints.permits(getKeyUsagePrimitives(kuBit), eeCert.getPublicKey()))
            {
                throw new CertPathValidatorException(
                    "Public key not permitted for '" + getKeyUsageName(kuBit) + "' KeyUsage");
            }
        }
    }

    private static void checkIssued(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate cert) throws CertPathValidatorException
    {
        String sigAlgName = getSigAlgName(cert, null);
        if (!JsseUtils.isNameSpecified(sigAlgName))
        {
            throw new CertPathValidatorException();
        }

        AlgorithmParameters sigAlgParams = getSigAlgParams(helper, cert);

        if (!algorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName, sigAlgParams))
        {
            throw new CertPathValidatorException();
        }
    }

    private static void checkIssuedBy(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate subjectCert, X509Certificate issuerCert) throws CertPathValidatorException
    {
        String sigAlgName = getSigAlgName(subjectCert, issuerCert);
        if (!JsseUtils.isNameSpecified(sigAlgName))
        {
            throw new CertPathValidatorException();
        }

        AlgorithmParameters sigAlgParams = getSigAlgParams(helper, subjectCert);

        if (!algorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName,
            issuerCert.getPublicKey(), sigAlgParams))
        {
            throw new CertPathValidatorException();
        }
    }

    static String getExtendedKeyUsageName(KeyPurposeId ekuOID)
    {
        if (KeyPurposeId.id_kp_clientAuth.equals(ekuOID))
        {
            return "clientAuth";
        }
        if (KeyPurposeId.id_kp_serverAuth.equals(ekuOID))
        {
            return "serverAuth";
        }
        return "(" + ekuOID + ")";
    }

    static String getKeyUsageName(int kuBit)
    {
        switch (kuBit)
        {
        case KU_DIGITAL_SIGNATURE:
            return "digitalSignature";
        case KU_KEY_ENCIPHERMENT:
            return "keyEncipherment";
        case KU_KEY_AGREEMENT:
            return "keyAgreement";
        default:
            return "(" + kuBit + ")";
        }
    }

    static Set<BCCryptoPrimitive> getKeyUsagePrimitives(int kuBit)
    {
        switch (kuBit)
        {
        case KU_KEY_AGREEMENT:
            return JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        case KU_KEY_ENCIPHERMENT:
            return JsseUtils.KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
        default:
            return JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;
        }
    }

    static String getSigAlgName(X509Certificate subjectCert, X509Certificate issuerCert)
    {
        String sigAlgOID = subjectCert.getSigAlgOID();

        // Enforce/provide standard names for some OIDs
        {
            String sigAlgName = sigAlgNames.get(sigAlgOID);
            if (null != sigAlgName)
            {
                return sigAlgName;
            }
        }

        /*
         * For the PSS OID, the name requires inspecting the parameters. We also want to ensure the
         * returned name is of the "...andMGF1" form rather than just "RSASSA-PSS".
         */
        if (PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(sigAlgOID))
        {
            RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(subjectCert.getSigAlgParams());
            if (null != pssParams)
            {
                ASN1ObjectIdentifier hashOID = pssParams.getHashAlgorithm().getAlgorithm();
                if (null != hashOID)
                {
                    X509Certificate keyCert = issuerCert;
                    if (null == keyCert)
                    {
                        /*
                         * TODO[jsse] Is there any better way to handle this? Distinguishing
                         * rsa_pss_pss_* from rsa_pss_rsae_* requires knowing the issuer's public
                         * key OID, but here the TA cert is not available. It happens most notably
                         * when choosing a certificate from the key manager, but also for imported
                         * trust managers that don't implement X509ExtendedTrustManager.
                         */
                        keyCert = subjectCert;
                    }

                    try
                    {
                        JcaTlsCertificate jcaKeyCert = new JcaTlsCertificate(null, keyCert);

                        if (NISTObjectIdentifiers.id_sha256.equals(hashOID))
                        {
                            if (jcaKeyCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha256))
                            {
                                return SIG_ALG_NAME_rsa_pss_pss_sha256;
                            }
                            if (jcaKeyCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_rsae_sha256))
                            {
                                return SIG_ALG_NAME_rsa_pss_rsae_sha256;
                            }
                        }
                        else if (NISTObjectIdentifiers.id_sha384.equals(hashOID))
                        {
                            if (jcaKeyCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha384))
                            {
                                return SIG_ALG_NAME_rsa_pss_pss_sha384;
                            }
                            if (jcaKeyCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_rsae_sha384))
                            {
                                return SIG_ALG_NAME_rsa_pss_rsae_sha384;
                            }
                        }
                        else if (NISTObjectIdentifiers.id_sha512.equals(hashOID))
                        {
                            if (jcaKeyCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha512))
                            {
                                return SIG_ALG_NAME_rsa_pss_pss_sha512;
                            }
                            if (jcaKeyCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_rsae_sha512))
                            {
                                return SIG_ALG_NAME_rsa_pss_rsae_sha512;
                            }
                        }
                    }
                    catch (IOException e)
                    {
                        // Ignore
                    }
                }
            }

            return null;
        }

        return subjectCert.getSigAlgName();
    }

    static AlgorithmParameters getSigAlgParams(JcaJceHelper helper, X509Certificate cert)
        throws CertPathValidatorException
    {
        byte[] encoded = cert.getSigAlgParams();
        if (null == encoded)
        {
            return null;
        }

        String sigAlgOID = cert.getSigAlgOID();
        if (sigAlgNoParams.contains(sigAlgOID) && Arrays.areEqual(DER_NULL_ENCODING, encoded))
        {
            return null;
        }

        AlgorithmParameters sigAlgParams;
        try
        {
            sigAlgParams = helper.createAlgorithmParameters(sigAlgOID);
        }
        catch (GeneralSecurityException e)
        {
            // TODO[jsse] Consider requiring 'encoded' to be DER_NULL_ENCODING here
            return null;
        }

        try
        {
            sigAlgParams.init(encoded);
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException(e);
        }

        return sigAlgParams;
    }

    static boolean isValidFIPSPublicKey(PublicKey publicKey)
    {
        /*
         * Require that 'id-ecPublicKey' algorithm is used only with 'namedCurve' parameters.
         */
        try
        {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            AlgorithmIdentifier algID = spki.getAlgorithm();
            if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algID.getAlgorithm()))
            {
                return true;
            }

            ASN1Encodable parameters = algID.getParameters().toASN1Primitive();
            if (null != parameters)
            {
                ASN1Primitive primitive = parameters.toASN1Primitive();
                if (primitive instanceof ASN1ObjectIdentifier)
                {
                    // TODO[fips] Consider further constraints here
//                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)primitive;
//                    int curve = NamedGroupInfo.getCurve(oid);
//                    return NamedGroup.refersToASpecificCurve(curve) && FipsUtils.isFipsNamedGroup(curve);
                    return true;
                }
            }
        }
        catch (Exception e)
        {
        }

        return false;
    }

    static boolean permitsKeyUsage(PublicKey publicKey, boolean[] ku, int kuBit, BCAlgorithmConstraints algorithmConstraints)
    {
        return supportsKeyUsage(ku, kuBit)
            && algorithmConstraints.permits(getKeyUsagePrimitives(kuBit), publicKey);
    }

    static boolean supportsExtendedKeyUsage(X509Certificate cert, KeyPurposeId ekuOID)
    {
        try
        {
            return supportsExtendedKeyUsage(cert.getExtendedKeyUsage(), ekuOID);
        }
        catch (CertificateParsingException e)
        {
            return false;
        }
    }

    static boolean supportsExtendedKeyUsage(List<String> eku, KeyPurposeId ekuOID)
    {
        return null == eku
            || eku.contains(ekuOID.getId())
            || eku.contains(KeyPurposeId.anyExtendedKeyUsage.getId());
    }

    static boolean supportsKeyUsage(X509Certificate cert, int kuBit)
    {
        return supportsKeyUsage(cert.getKeyUsage(), kuBit);
    }

    static boolean supportsKeyUsage(boolean[] ku, int kuBit)
    {
        return null == ku || (ku.length > kuBit && ku[kuBit]);
    }
}
