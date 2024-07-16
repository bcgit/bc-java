package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.internal.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.internal.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.internal.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Arrays;

class ProvOcspRevocationChecker
    implements PKIXCertRevocationChecker
{
    private static final Logger LOG = Logger.getLogger(ProvOcspRevocationChecker.class.getName());

    private static final Map oids = new HashMap();

    static
    {
        //
        // reverse mappings
        //
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        oids.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
        oids.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");

        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
    }

    private final JcaJceHelper helper;

    private PKIXCertRevocationCheckerParameters parameters;

    // properties from the parent PKIXRevocationChecker
    private Map<X509Certificate, byte[]> ocspResponses = new HashMap<X509Certificate, byte[]>();
    private List<Extension> ocspExtensions = new ArrayList<Extension>();
    private URI ocspResponder;
    private X509Certificate ocspResponderCert;

    public ProvOcspRevocationChecker(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public void setParameter(String name, Object value)
    {

    }

    public void initialize(PKIXCertRevocationCheckerParameters parameters)
    {
        this.parameters = parameters;
    }

    public void update(Map<X509Certificate, byte[]> ocspResponses, List<Extension> ocspExtensions, URI ocspResponder, X509Certificate ocspResponderCert)
    {
        this.ocspResponses = ocspResponses;
        this.ocspExtensions = ocspExtensions;
        this.ocspResponder = ocspResponder;
        this.ocspResponderCert = ocspResponderCert;
    }

    public List<CertPathValidatorException> getSoftFailExceptions()
    {
        return null;
    }

    public void init(boolean forForward)
        throws CertPathValidatorException
    {
        if (forForward)
        {
            throw new CertPathValidatorException("forward checking not supported");
        }

        this.parameters = null;
    }

    public void check(Certificate certificate)
        throws CertPathValidatorException
    {
        X509Certificate cert = (X509Certificate) certificate;
        LOG.info("[revocation check] OCSP check for cert: " + cert.getSubjectX500Principal());

        if (ocspResponses.get(cert) == null)
        {
            LOG.info("[revocation check] No stapled OCSP response found");
            try
            {
                OCSPResponse response = OcspResponseManager.getOCSPResponseForRevocationCheck(cert, parameters.getSigningCert(), ocspExtensions, ocspResponder, helper);
                if (response != null)
                {
                    ocspResponses.put(cert, response.getEncoded());
                }
            }
            catch (IOException e)
            {
                throw new CertPathValidatorException(
                          "unable to encode OCSP response", e, parameters.getCertPath(), parameters.getIndex());
            }
        }
        else
        {
            LOG.info("[revocation check] Found stapled OCSP response");
        }

        // get the nonce from the request extensions to validate the response later
        byte[] nonce = null;
        for (int i = 0; i < ocspExtensions.size(); i++)
        {
            Extension ext = ocspExtensions.get(i);
            byte[] value = ext.getValue();

            if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId().equals(ext.getId()))
            {
                nonce = value;
            }
        }

        // validate the OCSP responses
        if (!ocspResponses.isEmpty())
        {
            OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponses.get(cert));
            ASN1Integer serialNumber = new ASN1Integer(cert.getSerialNumber());

            if (ocspResponse != null)
            {
                if (OCSPResponseStatus.SUCCESSFUL == ocspResponse.getResponseStatus().getIntValue())
                {
                    ResponseBytes respBytes = ResponseBytes.getInstance(ocspResponse.getResponseBytes());

                    if (respBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic))
                    {
                        try
                        {
                            BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(respBytes.getResponse().getOctets());

                            if (validatedOcspResponse(basicResp, parameters, nonce, ocspResponderCert, helper))
                            {
                                ResponseData responseData = ResponseData.getInstance(basicResp.getTbsResponseData());

                                ASN1Sequence s = responseData.getResponses();

                                CertID certID = null;
                                for (int i = 0; i != s.size(); i++)
                                {
                                    SingleResponse resp = SingleResponse.getInstance(s.getObjectAt(i));

                                    if (serialNumber.equals(resp.getCertID().getSerialNumber()))
                                    {
                                        ASN1GeneralizedTime nextUp = resp.getNextUpdate();
                                        if (nextUp != null && parameters.getValidDate().after(nextUp.getDate()))
                                        {
                                            throw new ExtCertPathValidatorException("OCSP response expired");
                                        }
                                        if (certID == null || !certID.getHashAlgorithm().equals(resp.getCertID().getHashAlgorithm()))
                                        {
                                            org.bouncycastle.asn1.x509.Certificate issuer = extractCert();

                                            certID = createCertID(resp.getCertID(), issuer, serialNumber);
                                        }
                                        if (certID.equals(resp.getCertID()))
                                        {
                                            if (resp.getCertStatus().getTagNo() == 0)
                                            {
                                                // we're good!
                                                LOG.info("[revocation check] OCSP response successfully validated");
                                                return;
                                            }
                                            if (resp.getCertStatus().getTagNo() == 1)
                                            {
                                                RevokedInfo info = RevokedInfo.getInstance(resp.getCertStatus().getStatus());
                                                CRLReason reason = info.getRevocationReason();
                                                throw new CertPathValidatorException(
                                                    "certificate revoked, reason=(" + reason + "), date=" + info.getRevocationTime().getDate(),
                                                    null, parameters.getCertPath(), parameters.getIndex());
                                            }
                                            throw new CertPathValidatorException(
                                                "certificate revoked, details unknown",
                                                null, parameters.getCertPath(), parameters.getIndex());
                                        }
                                    }
                                }
                            }
                        }
                        catch (CertPathValidatorException e)
                        {
                            throw e;
                        }
                        catch (Exception e)
                        {
                            throw new CertPathValidatorException(
                                "unable to process OCSP response", e, parameters.getCertPath(), parameters.getIndex());
                        }
                    }
                }
                else
                {
                    throw new CertPathValidatorException(
                        "OCSP response failed: " + ocspResponse.getResponseStatus().getValue(),
                        null, parameters.getCertPath(), parameters.getIndex());
                }
            }
            else
            {
                // TODO: add checking for the OCSP extension (properly vetted)
                throw new RecoverableCertPathValidatorException(
                    "no OCSP response found for certificate", null, parameters.getCertPath(), parameters.getIndex());
            }
        }
        else
        {
            throw new RecoverableCertPathValidatorException(
                "no OCSP response found for any certificate", null, parameters.getCertPath(), parameters.getIndex());
        }
    }

    static boolean validatedOcspResponse(BasicOCSPResponse basicResp, PKIXCertRevocationCheckerParameters parameters, byte[] nonce, X509Certificate responderCert, JcaJceHelper helper)
        throws CertPathValidatorException
    {
        try
        {
            ASN1Sequence certs = basicResp.getCerts();

            Signature sig = helper.createSignature(getSignatureName(basicResp.getSignatureAlgorithm()));

            X509Certificate sigCert = getSignerCert(basicResp, parameters.getSigningCert(), responderCert, helper);
            if (sigCert == null && certs == null)
            {
                throw new CertPathValidatorException("OCSP responder certificate not found");
            }

            if (sigCert != null)
            {
                sig.initVerify(sigCert.getPublicKey());
            }
            else
            {
                CertificateFactory cf = helper.createCertificateFactory("X.509");

                X509Certificate ocspCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certs.getObjectAt(0).toASN1Primitive().getEncoded()));

                // check cert signed by CA
                ocspCert.verify(parameters.getSigningCert().getPublicKey());

                // check cert valid
                ocspCert.checkValidity(parameters.getValidDate());

                // check ID
                if (!responderMatches(basicResp.getTbsResponseData().getResponderID(), ocspCert, helper))
                {
                    throw new CertPathValidatorException("responder certificate does not match responderID", null,
                        parameters.getCertPath(), parameters.getIndex());
                }

                // TODO: RFC 6960 allows for a "no check" extension - where present it means the CA says the cert
                // will remain valid for it's lifetime. If any caching is added here that should be taken into account.

                // check we are valid
                List extendedKeyUsage = ocspCert.getExtendedKeyUsage();
                if (extendedKeyUsage == null || !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.getId()))
                {
                    throw new CertPathValidatorException("responder certificate not valid for signing OCSP responses", null,
                        parameters.getCertPath(), parameters.getIndex());
                }

                sig.initVerify(ocspCert);
            }

            sig.update(basicResp.getTbsResponseData().getEncoded(ASN1Encoding.DER));

            if (sig.verify(basicResp.getSignature().getOctets()))
            {
                if (nonce != null)
                {
                    Extensions exts = basicResp.getTbsResponseData().getResponseExtensions();

                    org.bouncycastle.asn1.x509.Extension ext = exts.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

                    if (!Arrays.areEqual(nonce, ext.getExtnValue().getOctets()))
                    {
                        throw new CertPathValidatorException("nonce mismatch in OCSP response", null, parameters.getCertPath(), parameters.getIndex());
                    }
                }
                return true;
            }

            return false;
        }
        catch (CertPathValidatorException e)
        {
            throw e;
        }
        catch (GeneralSecurityException e)
        {
            throw new CertPathValidatorException("OCSP response failure: " + e.getMessage(), e, parameters.getCertPath(), parameters.getIndex());
        }
        catch (IOException e)
        {
            throw new CertPathValidatorException("OCSP response failure: " + e.getMessage(), e, parameters.getCertPath(), parameters.getIndex());
        }
    }

    private static X509Certificate getSignerCert(BasicOCSPResponse basicResp, X509Certificate signingCert, X509Certificate responderCert, JcaJceHelper helper)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        ResponderID responderID = basicResp.getTbsResponseData().getResponderID();

        byte[] keyHash = responderID.getKeyHash();
        if (keyHash != null)
        {
            MessageDigest digest = helper.createMessageDigest("SHA1");
            X509Certificate sigCert = responderCert;

            if (sigCert != null)
            {
                if (Arrays.areEqual(keyHash, calcKeyHash(digest, sigCert.getPublicKey())))
                {
                    return sigCert;
                }
            }

            sigCert = signingCert;
            if (sigCert != null)
            {
                if (Arrays.areEqual(keyHash, calcKeyHash(digest, sigCert.getPublicKey())))
                {
                    return sigCert;
                }
            }
        }
        else
        {
            X500Name name = X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName());
            X509Certificate sigCert = responderCert;

            if (sigCert != null)
            {
                if (name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, sigCert.getSubjectX500Principal().getEncoded())))
                {
                    return sigCert;
                }
            }

            sigCert = signingCert;
            if (sigCert != null)
            {
                if (name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, sigCert.getSubjectX500Principal().getEncoded())))
                {
                    return sigCert;
                }
            }
        }

        return null;
    }

    private static boolean responderMatches(ResponderID responderID, X509Certificate certificate, JcaJceHelper helper)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        byte[] keyHash = responderID.getKeyHash();
        if (keyHash != null)
        {
            MessageDigest digest = helper.createMessageDigest("SHA1");

            return Arrays.areEqual(keyHash, calcKeyHash(digest, certificate.getPublicKey()));
        }
        else
        {
            X500Name name = X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName());

            return name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, certificate.getSubjectX500Principal().getEncoded()));
        }
    }

    private static byte[] calcKeyHash(MessageDigest digest, PublicKey key)
    {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(key.getEncoded());

        return digest.digest(info.getPublicKeyData().getBytes());
    }

    private org.bouncycastle.asn1.x509.Certificate extractCert()
        throws CertPathValidatorException
    {
        try
        {
            return org.bouncycastle.asn1.x509.Certificate.getInstance(parameters.getSigningCert().getEncoded());
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException("cannot process signing cert: " + e.getMessage(), e, parameters.getCertPath(), parameters.getIndex());
        }
    }

    private CertID createCertID(CertID base, org.bouncycastle.asn1.x509.Certificate issuer, ASN1Integer serialNumber)
        throws CertPathValidatorException
    {
        return createCertID(base.getHashAlgorithm(), issuer, serialNumber);
    }

    private CertID createCertID(AlgorithmIdentifier digestAlg, org.bouncycastle.asn1.x509.Certificate issuer, ASN1Integer serialNumber)
        throws CertPathValidatorException
    {
        try
        {
            MessageDigest digest = helper.createMessageDigest(MessageDigestUtils.getDigestName(digestAlg.getAlgorithm()));

            ASN1OctetString issuerNameHash = new DEROctetString(digest.digest(issuer.getSubject().getEncoded(ASN1Encoding.DER)));

            ASN1OctetString issuerKeyHash = new DEROctetString(digest.digest(
                issuer.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));

            return new CertID(digestAlg, issuerNameHash, issuerKeyHash, serialNumber);
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException("problem creating ID: " + e, e);
        }
    }

    // we need to remove the - to create a correct signature name
    private static String getDigestName(ASN1ObjectIdentifier oid)
    {
        String name = MessageDigestUtils.getDigestName(oid);

        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }

    private static String getSignatureName(
        AlgorithmIdentifier sigAlgId)
    {
        ASN1Encodable params = sigAlgId.getParameters();

        if (params != null && !DERNull.INSTANCE.equals(params))
        {
            if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
            {
                RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);
                return getDigestName(rsaParams.getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
            }
        }

        if (oids.containsKey(sigAlgId.getAlgorithm()))
        {
            return (String)oids.get(sigAlgId.getAlgorithm());
        }

        return sigAlgId.getAlgorithm().getId();
    }
}
