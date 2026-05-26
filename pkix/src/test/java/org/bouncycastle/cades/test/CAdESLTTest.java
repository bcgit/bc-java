package org.bouncycastle.cades.test;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CompleteRevocationRefs;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cades.CAdESLevel;
import org.bouncycastle.cades.CAdESLevelDetector;
import org.bouncycastle.cades.CAdESLongTermValuesUtil;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;

public class CAdESLTTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final AlgorithmIdentifier SHA256 =
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    private static KeyPair signKP;
    private static X509Certificate signCert;
    private static KeyPair caKP;
    private static X509Certificate caCert;
    private static X509CRL caCrl;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (signKP == null)
        {
            caKP = CMSTestUtil.makeKeyPair();
            caCert = CMSTestUtil.makeCertificate(caKP, "CN=CAdES B-LT test CA, C=AU",
                caKP, "CN=CAdES B-LT test CA, C=AU");

            signKP = CMSTestUtil.makeKeyPair();
            signCert = CMSTestUtil.makeCertificate(signKP, "CN=CAdES B-LT signer, C=AU",
                caKP, "CN=CAdES B-LT test CA, C=AU");

            caCrl = CMSTestUtil.makeCrl(caKP);
        }
    }

    /**
     * Build a B-B signature, attach CRL-based long-term values, and check
     * that all four B-LT unsigned attributes are present, decode correctly
     * (cert refs / values match the CA cert; rev refs / values match the
     * CRL), and the level detector reports B_LT once a sig timestamp has
     * been added.
     */
    public void testApplyLongTermValues()
        throws Exception
    {
        byte[] payload = "CAdES B-LT roundtrip payload".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(caCrl);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        assertEquals(CAdESLevel.B_B, CAdESLevelDetector.attainedLevel(signer));

        List<X509CertificateHolder> chainCerts = Collections.singletonList(caCh);
        List<X509CRLHolder> crls = Collections.singletonList(crlHolder);

        CMSSignedData lt = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(), chainCerts, crls, SHA256, digProv);

        SignerInformation ltSigner = (SignerInformation)lt.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = ltSigner.getUnsignedAttributes();
        assertNotNull(unsigned);

        // --- certificateRefs ---
        Attribute certRefsAttr = unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
        assertNotNull("certificateRefs must be present", certRefsAttr);
        ASN1Sequence refsSeq = (ASN1Sequence)certRefsAttr.getAttrValues().getObjectAt(0);
        assertEquals(1, refsSeq.size());
        OtherCertID certId = OtherCertID.getInstance(refsSeq.getObjectAt(0));
        assertEquals(NISTObjectIdentifiers.id_sha256.getId(),
            certId.getAlgorithmHash().getAlgorithm().getId());
        assertEquals(Hex.toHexString(MessageDigest.getInstance("SHA-256", BC).digest(caCert.getEncoded())),
            Hex.toHexString(certId.getCertHash()));

        // --- certValues ---
        Attribute certValuesAttr = unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certValues);
        assertNotNull("certValues must be present", certValuesAttr);
        ASN1Sequence valuesSeq = (ASN1Sequence)certValuesAttr.getAttrValues().getObjectAt(0);
        assertEquals(1, valuesSeq.size());
        assertTrue(Arrays.equals(caCert.getEncoded(),
            org.bouncycastle.asn1.x509.Certificate.getInstance(valuesSeq.getObjectAt(0)).getEncoded("DER")));

        // --- revocationRefs ---
        Attribute revRefsAttr = unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
        assertNotNull("revocationRefs must be present", revRefsAttr);
        CompleteRevocationRefs revRefs = CompleteRevocationRefs.getInstance(
            revRefsAttr.getAttrValues().getObjectAt(0));
        CrlOcspRef[] crlOcspRefs = revRefs.getCrlOcspRefs();
        assertEquals(1, crlOcspRefs.length);
        assertNotNull(crlOcspRefs[0].getCrlids());
        assertEquals(1, crlOcspRefs[0].getCrlids().getCrls().length);

        // --- revocationValues ---
        Attribute revValuesAttr = unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
        assertNotNull("revocationValues must be present", revValuesAttr);
        RevocationValues revValues = RevocationValues.getInstance(
            revValuesAttr.getAttrValues().getObjectAt(0));
        assertEquals(1, revValues.getCrlVals().length);
        assertTrue(Arrays.equals(caCrl.getEncoded(),
            revValues.getCrlVals()[0].getEncoded("DER")));

        // Detector: B-LT requires a signature-time-stamp too. Without one
        // it currently reports B-B (sig-ts is the gating prerequisite).
        assertEquals(CAdESLevel.B_B, CAdESLevelDetector.attainedLevel(ltSigner));
    }

    /**
     * Stack B-T + B-LT and assert the detector reports B_LT.
     */
    public void testFullStackReachesBLT()
        throws Exception
    {
        byte[] payload = "B-T plus B-LT".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(caCrl);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        // Reuse CAdESTTest's local-TSA wiring would create a circular dep;
        // mint inline.
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        byte[] imprint = org.bouncycastle.cades.CAdESSignatureTimestampUtil.computeSignatureImprint(
            signer, SHA256, digProv);
        org.bouncycastle.tsp.TimeStampToken token = CAdESTestHelpers.mintTsaToken(imprint);
        signed = org.bouncycastle.cades.CAdESSignatureTimestampUtil.applySignatureTimestamp(
            signed, signer.getSID(), token);

        signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        assertEquals(CAdESLevel.B_T, CAdESLevelDetector.attainedLevel(signer));

        CMSSignedData lt = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(),
            Collections.singletonList(caCh),
            Collections.singletonList(crlHolder),
            SHA256, digProv);

        SignerInformation ltSigner = (SignerInformation)lt.getSignerInfos().getSigners().iterator().next();
        assertEquals(CAdESLevel.B_LT, CAdESLevelDetector.attainedLevel(ltSigner));
    }

    /**
     * Apply long-term values with an OCSP response (no CRLs) and assert the
     * revocationValues / revocationRefs attributes populate the OCSP slots:
     * ocspVals carries the BasicOCSPResponse bytes, ocspids carries an
     * OcspResponsesID with the responder ID + producedAt + a SHA-256 hash
     * of the response.
     */
    public void testApplyLongTermValuesWithOcsp()
        throws Exception
    {
        byte[] payload = "CAdES B-LT with OCSP".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);

        // --- B-B signature ---
        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        // --- mint a local OCSP response from the CA over the signer's cert ---
        BasicOCSPResp ocspResp = mintOcspResponse(caCh, signCh, digProv);

        // --- apply B-LT with the OCSP response, no CRLs ---
        CMSSignedData lt = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(),
            Collections.singletonList(caCh),
            Collections.<X509CRLHolder>emptyList(),
            Collections.singletonList(ocspResp),
            SHA256, digProv);

        SignerInformation ltSigner = (SignerInformation)lt.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = ltSigner.getUnsignedAttributes();

        // revocationValues carries the OCSP response.
        RevocationValues revValues = RevocationValues.getInstance(
            unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues)
                .getAttrValues().getObjectAt(0));
        assertEquals("no CRL vals expected", 0, revValues.getCrlVals().length);
        BasicOCSPResponse[] ocspVals = revValues.getOcspVals();
        assertEquals(1, ocspVals.length);
        assertTrue("ocspVals must match the mint",
            Arrays.equals(ocspResp.getEncoded(), ocspVals[0].getEncoded("DER")));

        // revocationRefs carries the OcspListID with the producedAt + hash.
        CompleteRevocationRefs revRefs = CompleteRevocationRefs.getInstance(
            unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs)
                .getAttrValues().getObjectAt(0));
        CrlOcspRef[] refs = revRefs.getCrlOcspRefs();
        assertEquals(1, refs.length);
        assertNull("no crlids when there are no CRLs", refs[0].getCrlids());
        assertNotNull("ocspids must be populated", refs[0].getOcspids());
        OcspResponsesID[] ocspRespIds = refs[0].getOcspids().getOcspResponses();
        assertEquals(1, ocspRespIds.length);

        // The producedAt timestamp matches.
        assertEquals(ocspResp.getProducedAt(),
            ocspRespIds[0].getOcspIdentifier().getProducedAt().getDate());

        // The ocspRepHash matches a SHA-256 of the BasicOCSPResponse.
        byte[] expectedHash = MessageDigest.getInstance("SHA-256", BC).digest(ocspResp.getEncoded());
        assertEquals(Hex.toHexString(expectedHash),
            Hex.toHexString(ocspRespIds[0].getOcspRepHash().getHashValue()));
    }

    /**
     * Round-trip the LT material via the getters and run the self-consistency
     * validator on a freshly built B-LT signature.
     */
    public void testGettersAndSelfConsistencyValidator()
        throws Exception
    {
        byte[] payload = "CAdES B-LT self-consistency".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(caCrl);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        BasicOCSPResp ocsp = mintOcspResponse(caCh, signCh, digProv);

        CMSSignedData lt = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(),
            java.util.Collections.singletonList(caCh),
            java.util.Collections.singletonList(crlHolder),
            java.util.Collections.singletonList(ocsp),
            SHA256, digProv);
        SignerInformation ltSigner = (SignerInformation)lt.getSignerInfos().getSigners().iterator().next();

        // --- getters ---
        java.util.List<X509CertificateHolder> certs =
            CAdESLongTermValuesUtil.getCertificateValues(ltSigner);
        assertEquals(1, certs.size());
        assertEquals(caCh.getSubject(), certs.get(0).getSubject());

        java.util.List<X509CRLHolder> crls =
            CAdESLongTermValuesUtil.getCertificateRevocationLists(ltSigner);
        assertEquals(1, crls.size());
        assertEquals(crlHolder.getIssuer(), crls.get(0).getIssuer());

        java.util.List<BasicOCSPResp> ocsps =
            CAdESLongTermValuesUtil.getOcspResponses(ltSigner);
        assertEquals(1, ocsps.size());

        // --- validator ---
        CAdESLongTermValuesUtil.validateLongTermValues(ltSigner, digProv);

        // Empty / pre-LT signer returns empty lists for each getter.
        assertEquals(0, CAdESLongTermValuesUtil.getCertificateValues(signer).size());
        assertEquals(0, CAdESLongTermValuesUtil.getCertificateRevocationLists(signer).size());
        assertEquals(0, CAdESLongTermValuesUtil.getOcspResponses(signer).size());
    }

    /**
     * Tampering the certValues bytes after the fact breaks the
     * certificateRefs hash check; validateLongTermValues must throw.
     */
    public void testSelfConsistencyValidatorCatchesTampering()
        throws Exception
    {
        byte[] payload = "tamper detection".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(caCrl);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        CMSSignedData lt = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(),
            java.util.Collections.singletonList(caCh),
            java.util.Collections.singletonList(crlHolder),
            SHA256, digProv);

        // Splice a *different* cert into certValues (the signer cert
        // standing in for the CA cert) — the certificateRefs hash, computed
        // against the original CA cert, will no longer match.
        SignerInformation ltSigner = (SignerInformation)lt.getSignerInfos().getSigners().iterator().next();
        AttributeTable unsigned = ltSigner.getUnsignedAttributes();
        Attribute origCertValues = unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certValues);
        Attribute substituted = new Attribute(
            PKCSObjectIdentifiers.id_aa_ets_certValues,
            new org.bouncycastle.asn1.DERSet(
                new org.bouncycastle.asn1.DERSequence(signCh.toASN1Structure())));
        org.bouncycastle.asn1.ASN1EncodableVector original = unsigned.toASN1EncodableVector();
        org.bouncycastle.asn1.ASN1EncodableVector v = new org.bouncycastle.asn1.ASN1EncodableVector();
        for (int i = 0; i != original.size(); i++)
        {
            Attribute a = (Attribute)original.get(i);
            if (a.getAttrType().equals(PKCSObjectIdentifiers.id_aa_ets_certValues))
            {
                v.add(substituted);
            }
            else
            {
                v.add(a);
            }
        }
        final SignerInformation tampered = SignerInformation.replaceUnsignedAttributes(
            ltSigner, new AttributeTable(v));
        assertNotNull(origCertValues);

        try
        {
            CAdESLongTermValuesUtil.validateLongTermValues(tampered, digProv);
            fail("expected CAdESException for tampered certValues");
        }
        catch (org.bouncycastle.cades.CAdESException e)
        {
            // expected — message should mention the cert that no longer
            // has a matching ref.
            assertTrue(e.getMessage(), e.getMessage().contains("certificateRefs"));
        }
    }

    private static BasicOCSPResp mintOcspResponse(X509CertificateHolder caCh,
                                                  X509CertificateHolder signCh,
                                                  DigestCalculatorProvider digProv)
        throws Exception
    {
        DigestCalculator sha1 = digProv.get(
            new AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1));
        CertificateID certID = new CertificateID(sha1, caCh, signCh.getSerialNumber());

        BasicOCSPRespBuilder b = new BasicOCSPRespBuilder(new RespID(caCh.getSubject()));
        b.addResponse(certID, CertificateStatus.GOOD);

        ContentSigner ocspSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(caKP.getPrivate());
        return b.build(ocspSigner, new X509CertificateHolder[]{ caCh }, new Date());
    }
}
