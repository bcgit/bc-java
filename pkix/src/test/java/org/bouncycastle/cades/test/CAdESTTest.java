package org.bouncycastle.cades.test;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cades.CAdESLevel;
import org.bouncycastle.cades.CAdESLevelDetector;
import org.bouncycastle.cades.CAdESSignatureTimestampUtil;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Hex;

public class CAdESTTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final ASN1ObjectIdentifier TSA_POLICY = new ASN1ObjectIdentifier("1.2.3.4.5");

    private static KeyPair signKP;
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

    private TimeStampToken mintTsaToken(byte[] imprint)
        throws Exception
    {
        return CAdESTestHelpers.mintTsaToken(imprint);
    }
}
