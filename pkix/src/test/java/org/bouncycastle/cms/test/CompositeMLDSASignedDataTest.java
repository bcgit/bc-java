package org.bouncycastle.cms.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;

/**
 * CMS SignedData round-trip and PKIX CertPath validation tests for the eighteen Composite ML-DSA
 * parameter sets (draft-ietf-lamps-pq-composite-sigs). Plain JCA sign/verify for these sets is
 * already covered by CompositeSignaturesTest, and CompositeKEMEnvelopedDataTest covers the Composite
 * ML-KEM EnvelopedData path, but the Composite ML-DSA OIDs had no CMS SignedData or PKIX CertPath
 * (chain) coverage even though they are wired through DefaultCMSSignatureAlgorithmNameGenerator and
 * the DefaultSignatureAlgorithmIdentifierFinder used on the CMS and cert-path paths.
 */
public class CompositeMLDSASignedDataTest
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final byte[] DATA = "the composite ML-DSA cat sat on the CMS mat".getBytes();

    private static final String[] NAMES = {
        "MLDSA44-ECDSA-P256-SHA256", "MLDSA44-Ed25519-SHA512", "MLDSA44-RSA2048-PKCS15-SHA256", "MLDSA44-RSA2048-PSS-SHA256",
        "MLDSA65-ECDSA-P256-SHA512", "MLDSA65-ECDSA-P384-SHA512", "MLDSA65-ECDSA-brainpoolP256r1-SHA512", "MLDSA65-Ed25519-SHA512",
        "MLDSA65-RSA3072-PKCS15-SHA512", "MLDSA65-RSA3072-PSS-SHA512", "MLDSA65-RSA4096-PKCS15-SHA512", "MLDSA65-RSA4096-PSS-SHA512",
        "MLDSA87-ECDSA-P384-SHA512", "MLDSA87-ECDSA-P521-SHA512", "MLDSA87-ECDSA-brainpoolP384r1-SHA512", "MLDSA87-Ed448-SHAKE256",
        "MLDSA87-RSA3072-PSS-SHA512", "MLDSA87-RSA4096-PSS-SHA512"
    };

    private static final ASN1ObjectIdentifier[] OIDS = {
        IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512,
        IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256,
        IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512, IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512,
        IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512,
        IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512, IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512,
        IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512, IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512,
        IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512, IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512,
        IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256,
        IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512, IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512
    };

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static X509Certificate buildCert(X500Name issuer, PrivateKey issuerKey, String sigName,
                                             X500Name subject, PublicKey subjectKey, boolean ca, long serial)
        throws Exception
    {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, BigInteger.valueOf(serial), new Date(now - 3600000L), new Date(now + 365L * 24 * 3600000L),
            subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true,
            new KeyUsage(ca ? (KeyUsage.keyCertSign | KeyUsage.digitalSignature) : KeyUsage.digitalSignature));
        ContentSigner signer = new JcaContentSignerBuilder(sigName).setProvider(BC).build(issuerKey);
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(builder.build(signer));
    }

    public void testCompositeMLDSASignedData()
        throws Exception
    {
        for (int i = 0; i != NAMES.length; i++)
        {
            KeyPair kp = KeyPairGenerator.getInstance(NAMES[i], BC).generateKeyPair();
            X500Name dn = new X500Name("CN=" + NAMES[i]);
            X509Certificate cert = buildCert(dn, kp.getPrivate(), NAMES[i], dn, kp.getPublic(), true, 1);

            ContentSigner signer = new JcaContentSignerBuilder(NAMES[i]).setProvider(BC).build(kp.getPrivate());
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
                    .build(signer, new X509CertificateHolder(cert.getEncoded())));
            List certList = new ArrayList();
            certList.add(new X509CertificateHolder(cert.getEncoded()));
            gen.addCertificates(new CollectionStore(certList));

            CMSSignedData sd = new CMSSignedData(
                gen.generate(new CMSProcessableByteArray(DATA), true).getEncoded());

            SignerInformation signerInfo = sd.getSignerInfos().getSigners().iterator().next();

            assertEquals(NAMES[i] + ": SignerInfo signatureAlgorithm OID",
                OIDS[i].getId(), signerInfo.getEncryptionAlgOID());
            assertTrue(NAMES[i] + ": composite signature did not verify",
                signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)));

            // negative control: the same signature must not verify against a different composite key
            KeyPair other = KeyPairGenerator.getInstance(NAMES[i], BC).generateKeyPair();
            X509Certificate otherCert = buildCert(dn, other.getPrivate(), NAMES[i], dn, other.getPublic(), true, 9);
            assertFalse(NAMES[i] + ": composite signature verified against the wrong key",
                signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(otherCert)));
        }
    }

    public void testCompositeMLDSACertPath()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
        for (int i = 0; i != NAMES.length; i++)
        {
            KeyPair caKp = KeyPairGenerator.getInstance(NAMES[i], BC).generateKeyPair();
            X500Name caDn = new X500Name("CN=Composite CA " + NAMES[i]);
            X509Certificate caCert = buildCert(caDn, caKp.getPrivate(), NAMES[i], caDn, caKp.getPublic(), true, 1);

            KeyPair eeKp = KeyPairGenerator.getInstance(NAMES[i], BC).generateKeyPair();
            X509Certificate eeCert = buildCert(caDn, caKp.getPrivate(), NAMES[i],
                new X500Name("CN=Composite EE " + NAMES[i]), eeKp.getPublic(), false, 2);

            Set trust = new HashSet();
            trust.add(new TrustAnchor(caCert, null));

            CertPath cp = cf.generateCertPath(Collections.singletonList(eeCert));
            PKIXParameters params = new PKIXParameters(trust);
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX", BC).validate(cp, params);

            // negative control: an EE certificate signed by a different CA key must not validate
            KeyPair rogueKp = KeyPairGenerator.getInstance(NAMES[i], BC).generateKeyPair();
            X509Certificate rogueEe = buildCert(caDn, rogueKp.getPrivate(), NAMES[i],
                new X500Name("CN=Rogue EE " + NAMES[i]), eeKp.getPublic(), false, 3);
            CertPath badCp = cf.generateCertPath(Collections.singletonList(rogueEe));
            try
            {
                CertPathValidator.getInstance("PKIX", BC).validate(badCp, params);
                fail(NAMES[i] + ": CertPath validated an EE signed by a key outside the anchor");
            }
            catch (CertPathValidatorException expected)
            {
                // expected
            }
        }
    }

    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(CompositeMLDSASignedDataTest.class);
    }
}
