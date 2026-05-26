package org.bouncycastle.cades.test;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cades.CAdESArchiveTimestampUtil;
import org.bouncycastle.cades.CAdESLevel;
import org.bouncycastle.cades.CAdESLevelDetector;
import org.bouncycastle.cades.CAdESLongTermValuesUtil;
import org.bouncycastle.cades.CAdESSignatureTimestampUtil;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Hex;

public class CAdESLTATest
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
            caCert = CMSTestUtil.makeCertificate(caKP, "CN=CAdES B-LTA test CA, C=AU",
                caKP, "CN=CAdES B-LTA test CA, C=AU");

            signKP = CMSTestUtil.makeKeyPair();
            signCert = CMSTestUtil.makeCertificate(signKP, "CN=CAdES B-LTA signer, C=AU",
                caKP, "CN=CAdES B-LTA test CA, C=AU");

            caCrl = CMSTestUtil.makeCrl(caKP);
        }
    }

    /**
     * Stack B-B → B-T → B-LT → B-LTA and assert the resulting signature
     * carries id-aa-ets-archiveTimestampV2, the embedded TSA token covers
     * the canonical archive imprint, the level detector reports B_LTA,
     * and an idempotent canonicalisation: re-computing the imprint on the
     * upgraded signed-data (which now contains the archive-timestamp
     * attribute) yields the same digest because the canonicaliser strips
     * archive-timestamps before hashing.
     */
    public void testFullStackReachesBLTA()
        throws Exception
    {
        byte[] payload = "B-LTA full-stack payload".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(caCrl);

        // B-B
        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        // B-T
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        byte[] sigImprint = CAdESSignatureTimestampUtil.computeSignatureImprint(signer, SHA256, digProv);
        TimeStampToken sigToken = CAdESTestHelpers.mintTsaToken(sigImprint);
        signed = CAdESSignatureTimestampUtil.applySignatureTimestamp(signed, signer.getSID(), sigToken);

        // B-LT
        signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        List<X509CertificateHolder> chainCerts = Collections.singletonList(caCh);
        List<X509CRLHolder> crls = Collections.singletonList(crlHolder);
        signed = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(), chainCerts, crls, SHA256, digProv);

        signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        assertEquals(CAdESLevel.B_LT, CAdESLevelDetector.attainedLevel(signer));

        // B-LTA: compute imprint over the whole SignedData, mint TSA token, attach.
        byte[] archImprint = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(
            signed, SHA256, digProv);
        TimeStampToken archToken = CAdESTestHelpers.mintTsaToken(archImprint);
        CMSSignedData ltaSigned = CAdESArchiveTimestampUtil.applyArchiveTimestamp(
            signed, signer.getSID(), archToken);

        SignerInformation ltaSigner = (SignerInformation)ltaSigned.getSignerInfos().getSigners().iterator().next();

        // archive-timestamp unsigned attr is present.
        AttributeTable unsigned = ltaSigner.getUnsignedAttributes();
        Attribute archAttr = unsigned.get(CAdESArchiveTimestampUtil.id_aa_ets_archiveTimestampV2);
        assertNotNull("archive-time-stamp v2 must be present", archAttr);
        assertEquals(1, archAttr.getAttrValues().size());

        // Token re-parses and the imprint inside matches what we computed.
        TimeStampToken roundTrip = new TimeStampToken(
            ContentInfo.getInstance(archAttr.getAttrValues().getObjectAt(0)));
        assertEquals(Hex.toHexString(archImprint),
            Hex.toHexString(roundTrip.getTimeStampInfo().getMessageImprintDigest()));

        // B-LTA detection.
        assertEquals(CAdESLevel.B_LTA, CAdESLevelDetector.attainedLevel(ltaSigner));

        // Re-compute imprint on the LTA-upgraded SignedData. Because the
        // canonicaliser strips archive-timestamps before hashing, the
        // imprint must equal the one computed before the attribute was
        // added (i.e. the chain is renewable: applying another
        // archive-timestamp covers the same canonical input).
        byte[] renewedImprint = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(
            ltaSigned, SHA256, digProv);
        assertEquals("archive-timestamp imprint must be stable under archive-attribute presence",
            Hex.toHexString(archImprint), Hex.toHexString(renewedImprint));
    }

    /**
     * Two stacked archive-timestamps end up in the same attribute&apos;s
     * value-set (a typical renewal chain), not as separate Attribute
     * records.
     */
    public void testArchiveTimestampChainAppend()
        throws Exception
    {
        byte[] payload = "archive-timestamp renewal".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        byte[] imp1 = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(signed, SHA256, digProv);
        signed = CAdESArchiveTimestampUtil.applyArchiveTimestamp(
            signed, signer.getSID(), CAdESTestHelpers.mintTsaToken(imp1));

        byte[] imp2 = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(signed, SHA256, digProv);
        assertEquals("renewed archive imprint must equal the original",
            Hex.toHexString(imp1), Hex.toHexString(imp2));

        signed = CAdESArchiveTimestampUtil.applyArchiveTimestamp(
            signed, signer.getSID(), CAdESTestHelpers.mintTsaToken(imp2));

        SignerInformation finalSigner = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        Attribute archAttr = finalSigner.getUnsignedAttributes()
            .get(CAdESArchiveTimestampUtil.id_aa_ets_archiveTimestampV2);
        assertEquals("both archive-timestamps must be in one attribute",
            2, archAttr.getAttrValues().size());
    }

    /**
     * The streaming computeArchiveTimestampImprint(CMSSignedDataParser, ...)
     * variant produces the same digest as the in-memory variant when fed the
     * wire-form bytes of the same SignedData (github #1983). Exercised at
     * B-B, B-LT (so the certificates and CRLs fields are non-empty) and
     * B-LTA (so a SignerInfo carrying an archive-timestamp attribute is
     * present and the stripping path runs).
     */
    public void testStreamingImprintMatchesInMemory()
        throws Exception
    {
        byte[] payload = "streaming imprint test".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caCh = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(caCrl);

        // B-B baseline.
        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        assertImprintsMatch(signed, digProv, "B-B");

        // B-LT (adds certificates and CRLs to the SignedData).
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        signed = CAdESLongTermValuesUtil.applyLongTermValues(
            signed, signer.getSID(),
            Collections.singletonList(caCh),
            Collections.singletonList(crlHolder),
            SHA256, digProv);

        assertImprintsMatch(signed, digProv, "B-LT");

        // B-LTA (SignerInfo now carries an archive-timestamp; stripping must
        // produce the same canonical bytes in both code paths).
        signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        byte[] archImprint = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(signed, SHA256, digProv);
        signed = CAdESArchiveTimestampUtil.applyArchiveTimestamp(
            signed, signer.getSID(), CAdESTestHelpers.mintTsaToken(archImprint));

        assertImprintsMatch(signed, digProv, "B-LTA");
    }

    /**
     * Round-trip the archive-timestamp tokens via the getter and run the
     * self-consistency validator on a freshly built B-LTA signature, plus
     * a renewed (two-token chain) signature.
     */
    public void testGettersAndSelfConsistencyValidator()
        throws Exception
    {
        byte[] payload = "B-LTA self-consistency".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);
        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);
        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        // Pre-upgrade: getter returns empty, validator throws.
        assertEquals(0,
            CAdESArchiveTimestampUtil.getArchiveTimestamps(signer).size());
        try
        {
            CAdESArchiveTimestampUtil.validateArchiveTimestamps(signed, signer, digProv);
            fail("expected CAdESException for missing archive-time-stamp");
        }
        catch (org.bouncycastle.cades.CAdESException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("no archive-time-stamp"));
        }

        byte[] imp1 = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(signed, SHA256, digProv);
        TimeStampToken first = CAdESTestHelpers.mintTsaToken(imp1);
        signed = CAdESArchiveTimestampUtil.applyArchiveTimestamp(signed, signer.getSID(), first);
        signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        java.util.List<TimeStampToken> tokens =
            CAdESArchiveTimestampUtil.getArchiveTimestamps(signer);
        assertEquals(1, tokens.size());
        assertEquals(Hex.toHexString(imp1),
            Hex.toHexString(tokens.get(0).getTimeStampInfo().getMessageImprintDigest()));

        CAdESArchiveTimestampUtil.validateArchiveTimestamps(signed, signer, digProv);

        // Renew: append a second archive-timestamp; both must still validate
        // against the same canonical-stripped imprint.
        byte[] imp2 = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(signed, SHA256, digProv);
        TimeStampToken second = CAdESTestHelpers.mintTsaToken(imp2);
        signed = CAdESArchiveTimestampUtil.applyArchiveTimestamp(signed, signer.getSID(), second);
        signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();

        assertEquals(2, CAdESArchiveTimestampUtil.getArchiveTimestamps(signer).size());
        CAdESArchiveTimestampUtil.validateArchiveTimestamps(signed, signer, digProv);
    }

    /**
     * Tampering the encapsulated content (or any other canonicalised field)
     * after the archive-time-stamp was minted must cause
     * validateArchiveTimestamps to throw.
     */
    public void testSelfConsistencyValidatorCatchesTampering()
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder signCh = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder cb = new CAdESSignerInfoGeneratorBuilder(digProv);

        // Build SignedData A and timestamp it.
        CAdESSignedDataGenerator gA = new CAdESSignedDataGenerator();
        gA.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gA.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData sdA = gA.generate(new CMSProcessableByteArray("payload A".getBytes("UTF-8")), true);
        SignerInformation sigA = (SignerInformation)sdA.getSignerInfos().getSigners().iterator().next();
        byte[] impA = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(sdA, SHA256, digProv);
        TimeStampToken tokenA = CAdESTestHelpers.mintTsaToken(impA);
        sdA = CAdESArchiveTimestampUtil.applyArchiveTimestamp(sdA, sigA.getSID(), tokenA);
        sigA = (SignerInformation)sdA.getSignerInfos().getSigners().iterator().next();

        // Build SignedData B (different payload, same signer).
        CAdESSignedDataGenerator gB = new CAdESSignedDataGenerator();
        gB.addSignerInfoGenerator(cb.build(signerBuilder, signCh));
        gB.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));
        CMSSignedData sdB = gB.generate(new CMSProcessableByteArray("payload B".getBytes("UTF-8")), true);
        SignerInformation sigB = (SignerInformation)sdB.getSignerInfos().getSigners().iterator().next();

        // Splice A's archive-time-stamp attribute on top of sdB's signer.
        AttributeTable unsignedA = sigA.getUnsignedAttributes();
        Attribute archA = unsignedA.get(CAdESArchiveTimestampUtil.id_aa_ets_archiveTimestampV2);
        AttributeTable unsignedB = sigB.getUnsignedAttributes();
        if (unsignedB == null)
        {
            unsignedB = new AttributeTable(archA);
        }
        else
        {
            org.bouncycastle.asn1.ASN1EncodableVector v =
                new org.bouncycastle.asn1.ASN1EncodableVector();
            for (int i = 0; i != unsignedB.toASN1EncodableVector().size(); ++i)
            {
                v.add(unsignedB.toASN1EncodableVector().get(i));
            }
            v.add(archA);
            unsignedB = new AttributeTable(v);
        }
        SignerInformation tampered = SignerInformation.replaceUnsignedAttributes(sigB, unsignedB);
        CMSSignedData sdTampered = CMSSignedData.replaceSigners(sdB,
            new org.bouncycastle.cms.SignerInformationStore(
                java.util.Collections.singletonList(tampered)));

        try
        {
            CAdESArchiveTimestampUtil.validateArchiveTimestamps(sdTampered, tampered, digProv);
            fail("expected CAdESException for canonical-input mismatch");
        }
        catch (org.bouncycastle.cades.CAdESException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("imprint mismatch"));
        }
    }

    private static void assertImprintsMatch(CMSSignedData signed,
                                            DigestCalculatorProvider digProv,
                                            String label)
        throws Exception
    {
        byte[] inMemory = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(
            signed, SHA256, digProv);

        org.bouncycastle.cms.CMSSignedDataParser parser =
            new org.bouncycastle.cms.CMSSignedDataParser(digProv, signed.getEncoded());
        byte[] streamed = CAdESArchiveTimestampUtil.computeArchiveTimestampImprint(
            parser, SHA256, digProv);
        parser.close();

        assertEquals(label + ": streaming imprint must match in-memory imprint",
            Hex.toHexString(inMemory), Hex.toHexString(streamed));
    }
}
