package org.bouncycastle.cms.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.microsoft.MicrosoftObjectIdentifiers;
import org.bouncycastle.asn1.microsoft.TimeStampRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;

/**
 * End-to-end demo of the legacy Microsoft Authenticode time stamping protocol —
 * the {@code signtool /t} protocol, built on PKCS#9 countersignatures rather than
 * RFC 3161 (github issue #2005).
 *
 * <p><b>Read this before using.</b> This protocol is the pre-RFC 3161 one; Microsoft's
 * own tooling has long preferred RFC 3161 ({@code signtool /tr}), most public TSAs have
 * retired their legacy endpoints, and new designs should use the RFC 3161 support in
 * {@code org.bouncycastle.tsp}. BC therefore ships the wire-format request structure
 * ({@link TimeStampRequest org.bouncycastle.asn1.microsoft.TimeStampRequest}) but no
 * high-level protocol API — as this example shows, the existing CMS classes already
 * cover both ends of the exchange.</p>
 *
 * <p>The protocol, per
 * <a href="https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures">
 * Time Stamping Authenticode Signatures</a>:</p>
 * <ol>
 *   <li>Copy the signature (encryptedDigest) from the SignerInfo of the signed PKCS#7.</li>
 *   <li>HTTP POST a base64 encoded DER {@code TimeStampRequest} carrying that signature
 *       to the time stamp server (Content-Type {@code application/octet-stream}).</li>
 *   <li>Receive a base64 encoded PKCS#7 SignedData signed by the time stamper, whose
 *       content echoes the request and whose SignerInfo carries a signingTime
 *       signed attribute.</li>
 *   <li>Discard the response's ContentInfo; copy its SignerInfo into the original
 *       SignerInfo as a PKCS#9 countersignature (unsigned attribute 1.2.840.113549.1.9.6)
 *       and merge the time stamper's certificates into the original SignedData.</li>
 * </ol>
 *
 * <p>The example is self-contained: it stands up the time stamp service in-process
 * (rather than calling out to a remote one) so the flow can be exercised without
 * network access. In production steps (2)/(3) are an HTTP round-trip; BC deliberately
 * does not ship an HTTP client, so the caller picks a transport.</p>
 *
 * <p>One interop caveat: RFC 5652 sec. 11.4 forbids a content-type signed attribute in
 * a countersignature SignerInfo, and BC's {@link SignerInformation#verify} enforces
 * that. The local service here omits the attribute so the countersignature verifies;
 * historical Authenticode time stampers (PKCS#7 v1.5 vintage) included it, so
 * countersignatures lifted from old real-world responses may need their attributes
 * inspected manually rather than via {@code verify()}.</p>
 *
 * <p>Real Authenticode signatures are made over an SpcIndirectDataContent structure
 * (OID 1.3.6.1.4.1.311.2.1.4) embedding the PE image hash; building that structure is
 * out of scope here — the time stamping flow is identical whatever the signed content
 * is, so this example signs plain data.</p>
 */
public class AuthenticodeTimeStampExample
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // 1. Code signer and time stamper keypairs + self-signed certs.
        KeyPair signKp = generateRsaKeyPair();
        X509Certificate signCert = selfSignedCert(signKp, "CN=Authenticode signer, C=AU",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning));

        KeyPair tsaKp = generateRsaKeyPair();
        X509Certificate tsaCert = selfSignedCert(tsaKp, "CN=Local Authenticode TSA, C=AU",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        // 2. The signature to be time stamped. Real Authenticode encapsulates an
        //    SpcIndirectDataContent holding the PE image hash; plain data here.
        byte[] payload = "Authenticode time stamp demo payload".getBytes("UTF-8");

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKp.getPrivate()), signCert));
        gen.addCertificates(new JcaCertStore(Collections.singletonList(signCert)));

        CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(payload), true);
        SignerInformation signer = (SignerInformation)signedData.getSignerInfos().getSigners().iterator().next();

        // 3. Build the time stamp request: a ContentInfo of type data carrying the
        //    signature (encryptedDigest) of the SignerInfo to be countersigned. On the
        //    wire this is the HTTP POST body, base64 encoded, with the headers
        //    Content-Type: application/octet-stream and CacheControl: no-cache.
        TimeStampRequest tsReq = new TimeStampRequest(
            new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(signer.getSignature())));

        String requestBody = Base64.toBase64String(tsReq.getEncoded(ASN1Encoding.DER));
        System.out.println("Request body:           " + requestBody.length() + " chars base64");

        // 4. Time stamp service round-trip. In production this is an HTTP POST;
        //    here we drive the service in-process.
        String responseBody = localAuthenticodeTsa(requestBody, tsaCert, tsaKp);
        System.out.println("Response body:          " + responseBody.length() + " chars base64");

        // 5. Incorporate the time stamp: discard the response's ContentInfo, copy its
        //    SignerInfo into the original SignerInfo as a PKCS#9 countersignature, and
        //    merge the time stamper's certificates into the original SignedData.
        CMSSignedData tsResponse = new CMSSignedData(Base64.decode(responseBody));

        SignerInformation stampedSigner = SignerInformation.addCounterSigners(signer, tsResponse.getSignerInfos());
        CMSSignedData timeStamped = CMSSignedData.replaceSigners(signedData,
            new SignerInformationStore(Collections.singletonList(stampedSigner)));

        List<X509CertificateHolder> allCerts = new ArrayList<X509CertificateHolder>(
            timeStamped.getCertificates().getMatches(null));
        allCerts.addAll(tsResponse.getCertificates().getMatches(null));
        timeStamped = CMSSignedData.replaceCertificatesAndCRLs(timeStamped,
            new CollectionStore<X509CertificateHolder>(allCerts), null, null);

        // 6. Verify the original signature still validates, the countersignature
        //    validates over it, and pull out the certified signing time.
        CMSSignedData reloaded = new CMSSignedData(timeStamped.getEncoded());
        SignerInformation finalSigner = (SignerInformation)reloaded.getSignerInfos().getSigners().iterator().next();

        System.out.println("Signature valid:        " + finalSigner.verify(
            new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signCert)));

        SignerInformation timestamp = (SignerInformation)finalSigner.getCounterSignatures().getSigners().iterator().next();
        System.out.println("Countersignature valid: " + timestamp.verify(
            new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(tsaCert)));

        Time signingTime = Time.getInstance(
            timestamp.getSignedAttributes().get(CMSAttributes.signingTime).getAttrValues().getObjectAt(0));
        System.out.println("Time stamped at:        " + signingTime.getDate());
        System.out.println("CMS encoded length:     " + reloaded.getEncoded().length + " bytes");
    }

    /**
     * The time stamp service side of the exchange: decode and validate the request,
     * then return a SignedData over the presented signature bytes, carrying a
     * signingTime signed attribute and the service's certificate.
     */
    private static String localAuthenticodeTsa(String requestBody, X509Certificate tsaCert, KeyPair tsaKp)
        throws Exception
    {
        TimeStampRequest req = TimeStampRequest.getInstance(Base64.decode(requestBody));

        if (!MicrosoftObjectIdentifiers.microsoftTimeStampRequest.equals(req.getCountersignatureType()))
        {
            throw new IllegalArgumentException("not an Authenticode time stamp request");
        }
        if (!CMSObjectIdentifiers.data.equals(req.getContent().getContentType()))
        {
            throw new IllegalArgumentException("request content must be of type data");
        }

        byte[] signatureToStamp = ASN1OctetString.getInstance(req.getContent().getContent()).getOctets();

        // The SignerInfo produced here ends up as a countersignature, so per
        // RFC 5652 sec. 11.4 it must not carry a content-type signed attribute —
        // strip it from the default table (signingTime / messageDigest remain).
        CMSAttributeTableGenerator signedAttrs = new DefaultSignedAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                return super.getAttributes(parameters).remove(CMSAttributes.contentType);
            }
        };

        CMSSignedDataGenerator tsaGen = new CMSSignedDataGenerator();
        tsaGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
            .setSignedAttributeGenerator(signedAttrs)
            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(tsaKp.getPrivate()), tsaCert));
        tsaGen.addCertificates(new JcaCertStore(Collections.singletonList(tsaCert)));

        // The response content echoes the request content (the signature bytes).
        CMSSignedData response = tsaGen.generate(new CMSProcessableByteArray(signatureToStamp), true);

        return Base64.toBase64String(response.getEncoded());
    }

    private static KeyPair generateRsaKeyPair()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", BC);
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static X509Certificate selfSignedCert(KeyPair kp, String dn, ExtendedKeyUsage eku)
        throws Exception
    {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 60L * 60_000L);

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            new X500Name(dn), BigInteger.valueOf(1),
            notBefore, notAfter,
            new X500Name(dn),
            kp.getPublic());

        b.addExtension(Extension.extendedKeyUsage, true, eku);

        ContentSigner s = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(s));
    }
}
