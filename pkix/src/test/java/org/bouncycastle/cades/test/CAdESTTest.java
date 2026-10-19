package org.bouncycastle.cades.test;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cades.CAdESException;
import org.bouncycastle.cades.CAdESLevel;
import org.bouncycastle.cades.CAdESLevelDetector;
import org.bouncycastle.cades.CAdESSignatureTimestampUtil;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SigningCertificateVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class CAdESTTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final ASN1ObjectIdentifier TSA_POLICY = new ASN1ObjectIdentifier("1.2.3.4.5");

    private static KeyPair signKP;

    // a CMS signature with no signing-certificate attribute whose RSA public key was computed, after the signature
    // value was fixed, to verify the signed attributes; the signature value is what a time-stamp over it would cover
    private static final byte[] KEY_SUBSTITUTED_SIGNATURE = Base64.decode(
        "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" +
        "AAAAAAAA");

    private static X509Certificate signCert;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (signKP == null)
        {
            signKP = CMSTestUtil.makeKeyPair();
            signCert = CMSTestUtil.makeCertificate(signKP, "CN=CAdES B-T signer, C=AU",
                signKP, "CN=CAdES B-T signer, C=AU");
            // TSA cert/key are shared via CAdESTestHelpers; no fields needed.
        }
    }

    /**
     * Build a B-B signature, mint a local TSA token over the SignerInfo
     * signature value, attach it via the B-T helper, and check the
     * resulting attribute round-trips and the detector reports B_T.
     */
    public void testApplySignatureTimestamp()
        throws Exception
    {
        byte[] payload = "CAdES B-T roundtrip payload".getBytes("UTF-8");

        // --- B-B signature ---
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, ch));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData bb = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation signer = (SignerInformation)bb.getSignerInfos().getSigners().iterator().next();
        assertEquals("source signature must be B-B",
            CAdESLevel.B_B, CAdESLevelDetector.attainedLevel(signer));

        // --- compute the imprint ---
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        byte[] imprint = CAdESSignatureTimestampUtil.computeSignatureImprint(signer, sha256, digProv);

        // Cross-check the imprint against a fresh JCE digest.
        MessageDigest md = MessageDigest.getInstance("SHA-256", BC);
        byte[] expected = md.digest(signer.getSignature());
        assertEquals(Hex.toHexString(expected), Hex.toHexString(imprint));

        // --- mint a TSA token covering that imprint ---
        TimeStampToken tsToken = mintTsaToken(imprint);

        // --- upgrade to B-T ---
        CMSSignedData bt = CAdESSignatureTimestampUtil.applySignatureTimestamp(
            bb, signer.getSID(), tsToken);

        SignerInformation btSigner = (SignerInformation)bt.getSignerInfos().getSigners().iterator().next();

        // The original B-B attributes must still be present.
        assertNotNull(btSigner.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));

        // The signature-time-stamp unsigned attr is present and decodes.
        AttributeTable unsigned = btSigner.getUnsignedAttributes();
        assertNotNull(unsigned);
        Attribute tsAttr = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        assertNotNull("signature-time-stamp must be present", tsAttr);
        assertEquals(1, tsAttr.getAttrValues().size());

        // The token re-parses and its TSTInfo imprint matches what we sent.
        TimeStampToken roundTrip = new TimeStampToken(
            org.bouncycastle.asn1.cms.ContentInfo.getInstance(tsAttr.getAttrValues().getObjectAt(0)));
        byte[] tstImprint = roundTrip.getTimeStampInfo().getMessageImprintDigest();
        assertEquals(Hex.toHexString(imprint), Hex.toHexString(tstImprint));

        // Detector reports B-T.
        assertEquals(CAdESLevel.B_T, CAdESLevelDetector.attainedLevel(btSigner));

        // The original CMS signature must still verify (the unsigned attr
        // change is outside the signed-attribute table).
        assertTrue(btSigner.verify(
            new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(ch)));
    }

    /**
     * A second token applied to the same signer is appended to the existing
     * attribute&apos;s value set rather than replacing it.
     */
    public void testMultipleTimestampsAppend()
        throws Exception
    {
        byte[] payload = "CAdES B-T multiple-timestamp payload".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(cs, ch));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        byte[] imprint = CAdESSignatureTimestampUtil.computeSignatureImprint(signer, sha256, digProv);

        TimeStampToken first = mintTsaToken(imprint);
        signed = CAdESSignatureTimestampUtil.applySignatureTimestamp(signed, signer.getSID(), first);

        TimeStampToken second = mintTsaToken(imprint);
        signed = CAdESSignatureTimestampUtil.applySignatureTimestamp(signed, signer.getSID(), second);

        SignerInformation finalSigner = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        Attribute tsAttr = finalSigner.getUnsignedAttributes()
            .get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        assertEquals("both tokens must be present", 2, tsAttr.getAttrValues().size());
    }

    /**
     * Round-trip the timestamp tokens via the getter and run the
     * self-consistency validator on a freshly built B-T signature.
     */
    public void testGettersAndSelfConsistencyValidator()
        throws Exception
    {
        byte[] payload = "CAdES B-T self-consistency".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(cs, ch));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData bb = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation bbSigner = (SignerInformation)bb.getSignerInfos().getSigners().iterator().next();

        // Pre-upgrade: getter returns empty, validator throws.
        assertEquals(0,
            CAdESSignatureTimestampUtil.getSignatureTimestamps(bbSigner).size());
        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(bbSigner, digProv);
            fail("expected CAdESException for missing signature-time-stamp");
        }
        catch (org.bouncycastle.cades.CAdESException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("missing"));
        }

        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        byte[] imprint = CAdESSignatureTimestampUtil.computeSignatureImprint(bbSigner, sha256, digProv);
        TimeStampToken first = mintTsaToken(imprint);
        CMSSignedData bt = CAdESSignatureTimestampUtil.applySignatureTimestamp(
            bb, bbSigner.getSID(), first);
        SignerInformation btSigner = (SignerInformation)bt.getSignerInfos().getSigners().iterator().next();

        java.util.List<TimeStampToken> tokens =
            CAdESSignatureTimestampUtil.getSignatureTimestamps(btSigner);
        assertEquals(1, tokens.size());
        assertEquals(Hex.toHexString(imprint),
            Hex.toHexString(tokens.get(0).getTimeStampInfo().getMessageImprintDigest()));

        // The self-consistency validator passes.
        CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, digProv);

        // After appending a second token both should still validate.
        TimeStampToken second = mintTsaToken(imprint);
        bt = CAdESSignatureTimestampUtil.applySignatureTimestamp(bt, btSigner.getSID(), second);
        btSigner = (SignerInformation)bt.getSignerInfos().getSigners().iterator().next();
        assertEquals(2, CAdESSignatureTimestampUtil.getSignatureTimestamps(btSigner).size());
        CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, digProv);
    }

    /**
     * Timestamping a fresh imprint and then attaching it to a *different*
     * signer must cause validateSignatureTimestamps to throw &mdash; the
     * imprint covers the first signer's signature value, not the second's.
     */
    public void testSelfConsistencyValidatorCatchesImprintMismatch()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        // Two independent B-B signatures over different payloads (so the
        // SignerInfo.signature values differ).
        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);

        CAdESSignedDataGenerator g1 = new CAdESSignedDataGenerator();
        g1.addSignerInfoGenerator(cb.build(cs, ch));
        g1.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData sd1 = g1.generate(new CMSProcessableByteArray("payload one".getBytes("UTF-8")), true);
        SignerInformation s1 = (SignerInformation)sd1.getSignerInfos().getSigners().iterator().next();

        CAdESSignedDataGenerator g2 = new CAdESSignedDataGenerator();
        g2.addSignerInfoGenerator(cb.build(cs, ch));
        g2.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData sd2 = g2.generate(new CMSProcessableByteArray("payload two".getBytes("UTF-8")), true);
        SignerInformation s2 = (SignerInformation)sd2.getSignerInfos().getSigners().iterator().next();

        // Mint a token over s1's signature.
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        byte[] imprintForS1 = CAdESSignatureTimestampUtil.computeSignatureImprint(s1, sha256, digProv);
        TimeStampToken token = mintTsaToken(imprintForS1);

        // Attach it to s2 instead.
        CMSSignedData tampered = CAdESSignatureTimestampUtil.applySignatureTimestamp(
            sd2, s2.getSID(), token);
        SignerInformation tamperedSigner =
            (SignerInformation)tampered.getSignerInfos().getSigners().iterator().next();

        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(tamperedSigner, digProv);
            fail("expected CAdESException for imprint mismatch");
        }
        catch (org.bouncycastle.cades.CAdESException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("imprint mismatch"));
        }
    }


    /**
     * The verifier overload accepts a B-T signature built by the CAdES generator, whose signed attributes carry
     * the signing-certificate-v2 attribute.
     */
    public void testVerifierOverloadAcceptsBT()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(new CAdESSignerInfoGeneratorBuilder(digProv).build(cs, ch));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData bb = gen.generate(new CMSProcessableByteArray("CAdES B-T bound".getBytes("UTF-8")), true);
        SignerInformation bbSigner = (SignerInformation)bb.getSignerInfos().getSigners().iterator().next();

        ESSCertIDv2[] ids = SigningCertificateVerifier.getSigningCertificateIDs(bbSigner);
        assertEquals(1, ids.length);
        assertEquals(NISTObjectIdentifiers.id_sha256, ids[0].getHashAlgorithm().getAlgorithm());
        SigningCertificateVerifier.verifySigningCertificate(bbSigner, ch, digProv);

        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(ch);
        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(bbSigner, verifier);
            fail("expected CAdESException for missing signature-time-stamp");
        }
        catch (CAdESException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("missing"));
        }

        SignerInformation btSigner = timestamped(bb, bbSigner, digProv);
        CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, verifier);

        // a verifier without a certificate cannot bind anything
        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner,
                new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signKP.getPublic()));
            fail("expected IllegalArgumentException for a verifier without a certificate");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("verifier needs an associated certificate", e.getMessage());
        }
    }

    /**
     * A plain CMS signer carries no signing-certificate attribute: the imprint check alone passes, the verifier
     * overload refuses.
     */
    public void testVerifierOverloadRequiresSigningCertificate()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        CMSSignedData signed = plainSignature(null, null);
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        assertEquals(0, SigningCertificateVerifier.getSigningCertificateIDs(signer).length);

        SignerInformation btSigner = timestamped(signed, signer, digProv);
        CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, digProv);
        expectOverloadFailure(btSigner, "no signing-certificate attribute");
    }

    /**
     * A signing-certificate-v2 attribute naming some other hash does not bind the certificate.
     */
    public void testVerifierOverloadCatchesCertificateHashMismatch()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        byte[] wrongHash = new byte[32];
        java.util.Arrays.fill(wrongHash, (byte)1);
        final Attribute wrong = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
            new DERSet(new SigningCertificateV2(new ESSCertIDv2(wrongHash))));
        CMSSignedData signed = plainSignature(new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                return new DefaultSignedAttributeTableGenerator().getAttributes(parameters)
                    .add(wrong.getAttrType(), wrong.getAttrValues().getObjectAt(0));
            }
        }, null);
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        assertEquals(1, SigningCertificateVerifier.getSigningCertificateIDs(signer).length);

        expectOverloadFailure(timestamped(signed, signer, digProv), "hash does not match");
    }

    /**
     * The attribute binds nothing from the unsigned attributes, where RFC 5035 forbids it.
     */
    public void testVerifierOverloadRejectsUnsignedSigningCertificate()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);
        MessageDigest md = MessageDigest.getInstance("SHA-256", BC);
        final Attribute right = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
            new DERSet(new SigningCertificateV2(new ESSCertIDv2(md.digest(ch.getEncoded())))));
        CMSSignedData signed = plainSignature(null, new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
            {
                return new AttributeTable(right);
            }
        });
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        try
        {
            SigningCertificateVerifier.getSigningCertificateIDs(signer);
            fail("expected CMSException for an unsigned signing-certificate attribute");
        }
        catch (CMSException e)
        {
            assertEquals("signing-certificate attribute must be a signed attribute", e.getMessage());
        }

        expectOverloadFailure(timestamped(signed, signer, digProv), "must be a signed attribute");
    }

    /**
     * The overload verifies the signature under the verifier's certificate before anything else.
     */
    public void testVerifierOverloadRejectsWrongCertificate()
        throws Exception
    {
        // made before signing: its notBefore is the time of creation, so made after it could postdate signingTime
        KeyPair otherKP = CMSTestUtil.makeKeyPair();
        X509Certificate otherCert = CMSTestUtil.makeCertificate(otherKP, "CN=Other, C=AU", otherKP, "CN=Other, C=AU");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(new CAdESSignerInfoGeneratorBuilder(digProv).build(cs, ch));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData bb = gen.generate(new CMSProcessableByteArray("CAdES B-T other cert".getBytes("UTF-8")), true);
        SignerInformation bbSigner = (SignerInformation)bb.getSignerInfos().getSigners().iterator().next();
        SignerInformation btSigner = timestamped(bb, bbSigner, digProv);

        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner,
                new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(otherCert));
            fail("expected CAdESException for the wrong certificate");
        }
        catch (CAdESException e)
        {
            assertEquals("signature does not verify under the verifier's certificate", e.getMessage());
        }
    }

    /**
     * A signature whose key was chosen after its value verifies as a CMS signature and its time-stamp imprint is
     * consistent, since neither involves the key; only the certificate binding tells it apart.
     */
    public void testKeySubstitutedSignatureRejected()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        CMSSignedData signed = new CMSSignedData(KEY_SUBSTITUTED_SIGNATURE);
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        X509CertificateHolder ch = (X509CertificateHolder)signed.getCertificates().getMatches(signer.getSID()).iterator().next();
        SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(ch);

        assertTrue("signature must verify under the certificate it was presented with", signer.verify(verifier));
        assertEquals(0, SigningCertificateVerifier.getSigningCertificateIDs(signer).length);

        SignerInformation btSigner = timestamped(signed, signer, digProv);
        CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, digProv);
        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, verifier);
            fail("expected CAdESException for an unbound certificate");
        }
        catch (CAdESException e)
        {
            assertEquals("no signing-certificate attribute in signed attributes", e.getMessage());
        }
    }

    private CMSSignedData plainSignature(CMSAttributeTableGenerator signedGen, CMSAttributeTableGenerator unsignedGen)
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        JcaSignerInfoGeneratorBuilder b = new JcaSignerInfoGeneratorBuilder(digProv);
        if (signedGen != null)
        {
            b.setSignedAttributeGenerator(signedGen);
        }
        if (unsignedGen != null)
        {
            b.setUnsignedAttributeGenerator(unsignedGen);
        }
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(b.build(cs, signCert));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        return gen.generate(new CMSProcessableByteArray("plain CMS signature".getBytes("UTF-8")), true);
    }

    private SignerInformation timestamped(CMSSignedData signed, SignerInformation signer, DigestCalculatorProvider digProv)
        throws Exception
    {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        byte[] imprint = CAdESSignatureTimestampUtil.computeSignatureImprint(signer, sha256, digProv);
        CMSSignedData bt = CAdESSignatureTimestampUtil.applySignatureTimestamp(signed, signer.getSID(), mintTsaToken(imprint));
        return (SignerInformation)bt.getSignerInfos().getSigners().iterator().next();
    }

    private void expectOverloadFailure(SignerInformation btSigner, String message)
        throws Exception
    {
        try
        {
            CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner,
                new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signCert));
            fail("expected CAdESException: " + message);
        }
        catch (CAdESException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains(message));
        }
    }

    private TimeStampToken mintTsaToken(byte[] imprint)
        throws Exception
    {
        return CAdESTestHelpers.mintTsaToken(imprint);
    }
}
