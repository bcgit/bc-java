package org.bouncycastle.cades.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CompleteRevocationRefs;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cades.CAdESLevelDetector;
import org.bouncycastle.cades.CAdESLongTermValuesUtil;
import org.bouncycastle.cades.CAdESSignatureTimestampUtil;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * End-to-end CAdES B-B → B-T → B-LT walkthrough, attaching long-term
 * validation data (cert chain + CRL) on top of an RFC 3161 signature
 * time-stamp.
 *
 * <p>Per ETSI EN 319 122-1 / RFC 5126 the B-LT level guarantees that a
 * relying party can validate the signature in the future against the
 * snapshot of trust material captured at signing time, even after the CA
 * cert has expired or the CRL distribution point has gone offline. The four
 * unsigned attributes added are:</p>
 * <ul>
 *   <li>{@code id-aa-ets-certificateRefs} — SHA-256 references + IssuerSerial
 *       for each non-signer cert in the path.</li>
 *   <li>{@code id-aa-ets-certValues} — the raw cert bytes.</li>
 *   <li>{@code id-aa-ets-revocationRefs} — SHA-256 references for each CRL /
 *       OCSP response.</li>
 *   <li>{@code id-aa-ets-revocationValues} — the raw CRL / OCSP-response
 *       bytes.</li>
 * </ul>
 *
 * <p>This example uses a single CA-signed signer cert and a CRL from that
 * CA. {@link CAdESLongTermValuesUtil#applyLongTermValues(CMSSignedData,
 * org.bouncycastle.cms.SignerId, List, List, List, AlgorithmIdentifier,
 * DigestCalculatorProvider)} also accepts a {@code List&lt;BasicOCSPResp&gt;}
 * for OCSP-based deployments; the assembly logic is identical.</p>
 *
 * <p>{@link CAdESLevelDetector} requires a signature time-stamp to be
 * already present before it will report {@code B_LT} — without B-T, the
 * detector keeps reporting {@code B_B} regardless of the LT attributes. This
 * example shows the full B-B → B-T → B-LT progression.</p>
 */
public class CAdESLongTermExample
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final AlgorithmIdentifier SHA256 =
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // 1. CA, signer (CA-signed), TSA (self-signed with TSA EKU).
        KeyPair caKp = generateRsaKeyPair();
        X509Certificate caCert = selfSignedCert(caKp, "CN=CAdES B-LT demo CA, C=AU", null);

        KeyPair signKp = generateRsaKeyPair();
        X509Certificate signCert = caSignedCert(signKp, "CN=CAdES B-LT signer, C=AU",
            caKp, "CN=CAdES B-LT demo CA, C=AU");

        KeyPair tsaKp = generateRsaKeyPair();
        X509Certificate tsaCert = selfSignedCert(tsaKp, "CN=CAdES B-LT demo TSA, C=AU",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        // 2. CA issues a CRL (no entries for the signer — i.e. it's not
        //    revoked at signing time).
        X509CRL crl = issueCrl(caKp, "CN=CAdES B-LT demo CA, C=AU");

        // 3. CAdES B-B signature.
        byte[] payload = "CAdES B-LT demo payload".getBytes("UTF-8");
        DigestCalculatorProvider digProv =
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner contentSigner =
            new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKp.getPrivate());
        X509CertificateHolder signerHolder = new JcaX509CertificateHolder(signCert);
        X509CertificateHolder caHolder = new JcaX509CertificateHolder(caCert);
        X509CRLHolder crlHolder = new JcaX509CRLHolder(crl);

        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(
            new CAdESSignerInfoGeneratorBuilder(digProv).build(contentSigner, signerHolder));
        gen.addCertificates(new JcaCertStore(Collections.singletonList(signCert)));
        CMSSignedData bb = gen.generate(new CMSProcessableByteArray(payload), /*encapsulate=*/ true);
        SignerInformation bbSigner =
            (SignerInformation)bb.getSignerInfos().getSigners().iterator().next();
        System.out.println("After signing:         " + CAdESLevelDetector.attainedLevel(bbSigner));

        // 4. Upgrade B-B → B-T with a signature time-stamp.
        byte[] imprint =
            CAdESSignatureTimestampUtil.computeSignatureImprint(bbSigner, SHA256, digProv);
        TimeStampToken token = LocalTsa.mint(imprint, tsaCert, tsaKp);
        CMSSignedData bt = CAdESSignatureTimestampUtil.applySignatureTimestamp(
            bb, bbSigner.getSID(), token);
        SignerInformation btSigner =
            (SignerInformation)bt.getSignerInfos().getSigners().iterator().next();
        System.out.println("After sig timestamp:   " + CAdESLevelDetector.attainedLevel(btSigner));

        // 5. Upgrade B-T → B-LT by attaching the CA cert and its CRL.
        CMSSignedData lt = CAdESLongTermValuesUtil.applyLongTermValues(
            bt, btSigner.getSID(),
            Collections.singletonList(caHolder),
            Collections.singletonList(crlHolder),
            SHA256, digProv);
        SignerInformation ltSigner =
            (SignerInformation)lt.getSignerInfos().getSigners().iterator().next();
        System.out.println("After LT values:       " + CAdESLevelDetector.attainedLevel(ltSigner));

        // 6. Confirm the LT attributes are populated and the outer CMS still
        //    verifies (the unsigned-attribute changes are outside the signed
        //    attribute table).
        AttributeTable unsigned = ltSigner.getUnsignedAttributes();
        System.out.println("certificateRefs present:    "
            + (unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs) != null));
        System.out.println("certValues present:         "
            + (unsigned.get(PKCSObjectIdentifiers.id_aa_ets_certValues) != null));
        System.out.println("revocationRefs present:     "
            + (unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs) != null));
        System.out.println("revocationValues present:   "
            + (unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null));

        RevocationValues revValues = RevocationValues.getInstance(
            unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues)
                .getAttrValues().getObjectAt(0));
        System.out.println("CRLs in revValues:          " + revValues.getCrlVals().length);

        CompleteRevocationRefs revRefs = CompleteRevocationRefs.getInstance(
            unsigned.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs)
                .getAttrValues().getObjectAt(0));
        System.out.println("CrlOcspRefs in revRefs:     " + revRefs.getCrlOcspRefs().length);

        boolean stillValid = ltSigner.verify(
            new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signerHolder));
        System.out.println("Outer signature valid:      " + stillValid);
        System.out.println("CMS encoded length:         " + lt.getEncoded().length + " bytes");

        // Pull the LT material back out — these are the holders a relying
        // party would feed into a JCA CertPathValidator at a later date.
        System.out.println("Embedded certs:             "
            + CAdESLongTermValuesUtil.getCertificateValues(ltSigner).size());
        System.out.println("Embedded CRLs:              "
            + CAdESLongTermValuesUtil.getCertificateRevocationLists(ltSigner).size());

        // Self-consistency check: every ref's hash matches its value.
        CAdESLongTermValuesUtil.validateLongTermValues(ltSigner, digProv);
        System.out.println("LT self-consistency:        PASS");
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
        return signCert(dn, kp.getPublic(), dn, kp, eku);
    }

    private static X509Certificate caSignedCert(KeyPair subjectKp, String subjectDn,
                                                KeyPair issuerKp, String issuerDn)
        throws Exception
    {
        return signCert(subjectDn, subjectKp.getPublic(), issuerDn, issuerKp, null);
    }

    private static X509Certificate signCert(String subjectDn, java.security.PublicKey subjectPub,
                                            String issuerDn, KeyPair issuerKp,
                                            ExtendedKeyUsage eku)
        throws Exception
    {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 60L * 60_000L);

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
            new X500Name(issuerDn), BigInteger.valueOf(System.nanoTime()),
            notBefore, notAfter,
            new X500Name(subjectDn),
            subjectPub);
        if (eku != null)
        {
            b.addExtension(Extension.extendedKeyUsage, true, eku);
        }
        ContentSigner cs =
            new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(cs));
    }

    /**
     * Issue a CRL signed by the CA. No entries — the signer is in good
     * standing at signing time; the LT bundle captures that snapshot.
     */
    private static X509CRL issueCrl(KeyPair caKp, String caDn)
        throws Exception
    {
        Date now = new Date();
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(caDn), now);
        b.setNextUpdate(new Date(now.getTime() + 24L * 60 * 60 * 1000));
        // Placeholder entry against a serial we never issued, so the
        // CRL isn't empty (some validators reject empty CRLs).
        b.addCRLEntry(BigInteger.valueOf(0xCA), now, CRLReason.unspecified);

        ContentSigner cs =
            new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(caKp.getPrivate());
        return new JcaX509CRLConverter().setProvider(BC).getCRL(b.build(cs));
    }
}
