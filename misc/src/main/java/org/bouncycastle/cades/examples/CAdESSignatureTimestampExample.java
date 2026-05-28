package org.bouncycastle.cades.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cades.CAdESLevel;
import org.bouncycastle.cades.CAdESLevelDetector;
import org.bouncycastle.cades.CAdESSignatureTimestampUtil;
import org.bouncycastle.cades.CAdESSignedDataGenerator;
import org.bouncycastle.cades.CAdESSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
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
import org.bouncycastle.util.encoders.Hex;

/**
 * End-to-end demo of attaching an RFC 3161 signature time-stamp to a CAdES
 * signature — upgrading a CAdES B-B signature to CAdES B-T per RFC 5126
 * sec. 6.1.1 / ETSI EN 319 122-1 sec. 5.3.
 *
 * <p>The example is self-contained: it stands up a local TSA (rather than
 * calling out to a remote one) so the flow can be exercised without network
 * access. Steps:</p>
 * <ol>
 *   <li>Generate signer and TSA keypairs / self-signed certs.</li>
 *   <li>Produce a CAdES B-B detached signature over a payload.</li>
 *   <li>Compute the signature-time-stamp {@code MessageImprint} via
 *       {@link CAdESSignatureTimestampUtil#computeSignatureImprint} — the
 *       digest of {@code SignerInfo.signature}, not the whole CMS.</li>
 *   <li>Submit the imprint to the local TSA, receive an RFC 3161
 *       {@link TimeStampToken}.</li>
 *   <li>Attach the token as an {@code id-aa-signatureTimeStampToken}
 *       unsigned attribute via
 *       {@link CAdESSignatureTimestampUtil#applySignatureTimestamp}.</li>
 *   <li>Verify the upgraded signature still validates, that the token
 *       round-trips, and that {@link CAdESLevelDetector} now reports
 *       {@link CAdESLevel#B_T}.</li>
 * </ol>
 *
 * <p>In a production setting step (4) would be an HTTP POST to a public TSA;
 * BC deliberately does not ship an HTTP client, so the caller picks a
 * transport.</p>
 */
public class CAdESSignatureTimestampExample
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // 1. Signer and TSA keypairs + self-signed certs.
        KeyPair signKp = generateRsaKeyPair();
        X509Certificate signCert = selfSignedCert(signKp, "CN=CAdES B-T signer, C=AU", null);

        KeyPair tsaKp = generateRsaKeyPair();
        X509Certificate tsaCert = selfSignedCert(tsaKp, "CN=Local TSA, C=AU",
            new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        // 2. CAdES B-B detached signature.
        byte[] payload = "CAdES B-T demo payload".getBytes("UTF-8");
        DigestCalculatorProvider digProv =
            new JcaDigestCalculatorProviderBuilder().setProvider(BC).build();
        ContentSigner contentSigner =
            new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signKp.getPrivate());
        X509CertificateHolder signerHolder = new JcaX509CertificateHolder(signCert);

        CAdESSignedDataGenerator gen = new CAdESSignedDataGenerator();
        gen.addSignerInfoGenerator(
            new CAdESSignerInfoGeneratorBuilder(digProv).build(contentSigner, signerHolder));
        gen.addCertificates(new JcaCertStore(Collections.singletonList(signCert)));
        CMSSignedData bb = gen.generate(new CMSProcessableByteArray(payload), /*encapsulate=*/ true);

        SignerInformation signer = (SignerInformation)bb.getSignerInfos().getSigners().iterator().next();
        System.out.println("Pre-timestamp level:   " + CAdESLevelDetector.attainedLevel(signer));

        // 3. Compute the imprint (= digest of SignerInfo.signature).
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        byte[] imprint = CAdESSignatureTimestampUtil.computeSignatureImprint(signer, sha256, digProv);
        System.out.println("Signature imprint:     " + Hex.toHexString(imprint));

        // 4. TSA round-trip. In production this is a network round-trip;
        //    here we drive the local TSA in-process.
        TimeStampToken token = LocalTsa.mint(imprint, tsaCert, tsaKp);

        // 5. Attach the token as id-aa-signatureTimeStampToken.
        CMSSignedData bt = CAdESSignatureTimestampUtil.applySignatureTimestamp(
            bb, signer.getSID(), token);
        SignerInformation btSigner =
            (SignerInformation)bt.getSignerInfos().getSigners().iterator().next();

        // 6. Verify.
        boolean stillValid = btSigner.verify(
            new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(signerHolder));
        System.out.println("Outer signature valid: " + stillValid);

        // Pull the embedded timestamp tokens back out and self-consistency
        // check each one against signer.getSignature() under its own hash
        // algorithm.
        java.util.List<TimeStampToken> tokens =
            CAdESSignatureTimestampUtil.getSignatureTimestamps(btSigner);
        System.out.println("Embedded tokens:       " + tokens.size());

        byte[] tstImprint = tokens.get(0).getTimeStampInfo().getMessageImprintDigest();
        System.out.println("Token imprint match:   "
            + java.util.Arrays.equals(imprint, tstImprint));

        // Cross-check the imprint independently against a fresh JCE digest.
        byte[] expected = MessageDigest.getInstance("SHA-256", BC).digest(signer.getSignature());
        System.out.println("Imprint = SHA-256(sig):" + java.util.Arrays.equals(expected, imprint));

        CAdESSignatureTimestampUtil.validateSignatureTimestamps(btSigner, digProv);
        System.out.println("B-T self-consistency:  PASS");

        System.out.println("Post-timestamp level:  " + CAdESLevelDetector.attainedLevel(btSigner));
        System.out.println("CMS encoded length:    " + bt.getEncoded().length + " bytes");
    }

    private static KeyPair generateRsaKeyPair()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", BC);
        g.initialize(2048);
        return g.generateKeyPair();
    }

    /**
     * Self-signed cert with optional EKU (used to mark the TSA cert with
     * critical id-kp-timeStamping).
     */
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

        if (eku != null)
        {
            b.addExtension(Extension.extendedKeyUsage, true, eku);
        }

        ContentSigner s = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(s));
    }
}
