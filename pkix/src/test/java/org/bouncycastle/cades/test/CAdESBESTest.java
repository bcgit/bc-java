package org.bouncycastle.cades.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CommitmentTypeIdentifier;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;

public class CAdESBESTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

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
            signCert = CMSTestUtil.makeCertificate(signKP, "CN=CAdES test, O=Legion of the Bouncy Castle, C=AU",
                signKP, "CN=CAdES test, O=Legion of the Bouncy Castle, C=AU");
        }
    }

    /**
     * Build a CAdES-B-B signature with default settings and assert the
     * mandatory ESS signing-certificate-v2 attribute is present, references
     * the signing cert by issuer+serial, and carries a SHA-256 hash of the
     * cert.
     */
    public void testMandatorySigningCertificateV2()
        throws Exception
    {
        byte[] payload = "CAdES B-B mandatory ESS test payload".getBytes("UTF-8");

        CMSSignedData signed = signBES(payload, null, null);

        SignerInformationStore signers = signed.getSignerInfos();
        assertEquals(1, signers.size());
        SignerInformation signer = (SignerInformation)signers.getSigners().iterator().next();

        AttributeTable signedAttrs = signer.getSignedAttributes();
        assertNotNull(signedAttrs);

        // No legacy v1.
        assertNull("v1 must not be present by default",
            signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificate));

        SigningCertificateV2 sigCertV2 = SigningCertificateV2.getInstance(
            signedAttrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
                .getAttrValues().getObjectAt(0));
        assertNotNull(sigCertV2);

        ESSCertIDv2[] ids = sigCertV2.getCerts();
        assertEquals(1, ids.length);

        // Verify the certHash matches a SHA-256 of the signing cert.
        java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
        byte[] expectedHash = sha256.digest(signCert.getEncoded());
        assertEquals(Hex.toHexString(expectedHash),
            Hex.toHexString(ids[0].getCertHash()));

        // IssuerSerial matches.
        BigInteger gotSerial = ids[0].getIssuerSerial().getSerial().getValue();
        assertEquals(signCert.getSerialNumber(), gotSerial);

        // The SignedData itself must verify under the signing cert.
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);
        assertTrue(signer.verify(
            new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(BC).build(ch)));
    }

    /**
     * Verify optional CAdES B-B signed attributes round-trip via the builder
     * setters.
     */
    public void testOptionalCAdESAttributes()
        throws Exception
    {
        byte[] payload = "CAdES optional attributes test".getBytes("UTF-8");

        CommitmentTypeIndication commitment =
            new CommitmentTypeIndication(CommitmentTypeIdentifier.proofOfOrigin);
        SignerLocation loc = new SignerLocation(
            new org.bouncycastle.asn1.DERUTF8String("AU"),
            new org.bouncycastle.asn1.DERUTF8String("Melbourne"),
            (org.bouncycastle.asn1.ASN1Sequence)null);

        CMSSignedData signed = signBES(payload, commitment, loc);

        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        AttributeTable t = signer.getSignedAttributes();

        // commitment-type
        ASN1ObjectIdentifier commitOid = PKCSObjectIdentifiers.id_aa_ets_commitmentType;
        assertNotNull("commitmentType must be present", t.get(commitOid));
        CommitmentTypeIndication round = CommitmentTypeIndication.getInstance(
            t.get(commitOid).getAttrValues().getObjectAt(0));
        assertEquals(CommitmentTypeIdentifier.proofOfOrigin, round.getCommitmentTypeId());

        // signer-location
        ASN1ObjectIdentifier locOid = PKCSObjectIdentifiers.id_aa_ets_signerLocation;
        assertNotNull("signerLocation must be present", t.get(locOid));
    }

    /**
     * Opting into the legacy v1 ESS signing-certificate emits the v1 attr
     * with a SHA-1 cert hash and no v2 attr.
     */
    public void testLegacyV1OptIn()
        throws Exception
    {
        byte[] payload = "v1 opt-in".getBytes("UTF-8");

        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder b = new CAdESSignerInfoGeneratorBuilder(digProv)
            .setUseSigningCertificateV1(true);

        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(b.build(signerBuilder, ch));
        gen.addCertificate(ch);

        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);

        SignerInformation signer = (SignerInformation)signed.getSignerInfos().getSigners().iterator().next();
        AttributeTable t = signer.getSignedAttributes();

        assertNull("v2 must be absent in legacy mode",
            t.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));
        assertNotNull("v1 must be present in legacy mode",
            t.get(PKCSObjectIdentifiers.id_aa_signingCertificate));
    }

    private CMSSignedData signBES(byte[] payload,
                                  CommitmentTypeIndication commitment,
                                  SignerLocation signerLocation)
        throws Exception
    {
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKP.getPrivate());
        X509CertificateHolder ch = new JcaX509CertificateHolder(signCert);

        CAdESSignerInfoGeneratorBuilder b = new CAdESSignerInfoGeneratorBuilder(digProv);
        if (commitment != null)
        {
            b.setCommitmentType(commitment);
        }
        if (signerLocation != null)
        {
            b.setSignerLocation(signerLocation);
        }

        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(b.build(signerBuilder, ch));
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(signCert)));

        return gen.generate(new CMSProcessableByteArray(payload), true);
    }
}
