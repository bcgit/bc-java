package org.bouncycastle.tls.test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsECDomain;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

import junit.framework.TestCase;

/**
 * Test for TLS 1.3 with ShangMi (SM) cipher suites as defined in RFC 8998.
 */
public class SM2Tls13Test
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testSM2SignerAndVerifier_BC_BC()
        throws Exception
    {
        byte[] certificateEncoding;
        byte[] data;
        byte[] signature;

        {
            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
    
            AsymmetricCipherKeyPair keyPair = generateSM2KeyPair(crypto);
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.getPrivate();

            TlsCertificate tlsCertificate = createBCCertificate(keyPair, crypto);
            certificateEncoding = tlsCertificate.getEncoded();
            Certificate certChain = new Certificate(new TlsCertificate[]{ tlsCertificate });

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv13);
    
            TlsCredentialedSigner signer = new BcDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certChain,
                SignatureAndHashAlgorithm.sm2sig_sm3);

            data = new byte[64];
            crypto.getSecureRandom().nextBytes(data);

            TlsStreamSigner streamSigner = signer.getStreamSigner();
            OutputStream signerOutput = streamSigner.getOutputStream();
            signerOutput.write(data);
            signerOutput.close();
            signature = streamSigner.getSignature();

            assertNotNull(signature);
            assertTrue("Signature should be non‑empty", signature.length > 0);
        }

        {
            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

            TlsCertificate tlsCertificate = crypto.createCertificate(certificateEncoding);

            Tls13Verifier verifier = tlsCertificate.createVerifier(SignatureScheme.sm2sig_sm3);
            OutputStream verifierOutput = verifier.getOutputStream();
            verifierOutput.write(data);
            verifierOutput.close();
            assertTrue(verifier.verifySignature(signature));
        }
    }

    public void testSM2SignerAndVerifier_BC_JCA()
        throws Exception
    {
        byte[] certificateEncoding;
        byte[] data;
        byte[] signature;

        {
            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
    
            AsymmetricCipherKeyPair keyPair = generateSM2KeyPair(crypto);
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.getPrivate();

            TlsCertificate tlsCertificate = createBCCertificate(keyPair, crypto);
            certificateEncoding = tlsCertificate.getEncoded();
            Certificate certChain = new Certificate(new TlsCertificate[]{ tlsCertificate });

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv13);
    
            TlsCredentialedSigner signer = new BcDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certChain,
                SignatureAndHashAlgorithm.sm2sig_sm3);

            data = new byte[64];
            crypto.getSecureRandom().nextBytes(data);

            TlsStreamSigner streamSigner = signer.getStreamSigner();
            OutputStream signerOutput = streamSigner.getOutputStream();
            signerOutput.write(data);
            signerOutput.close();
            signature = streamSigner.getSignature();

            assertNotNull(signature);
            assertTrue("Signature should be non‑empty", signature.length > 0);
        }

        {
            JcaTlsCrypto crypto = new JcaTlsCryptoProvider().setProvider("BC").create(new SecureRandom());

            TlsCertificate tlsCertificate = crypto.createCertificate(certificateEncoding);

            Tls13Verifier verifier = tlsCertificate.createVerifier(SignatureScheme.sm2sig_sm3);
            OutputStream verifierOutput = verifier.getOutputStream();
            verifierOutput.write(data);
            verifierOutput.close();
            assertTrue(verifier.verifySignature(signature));
        }
    }

    public void testSM2SignerAndVerifier_JCA_BC()
        throws Exception
    {
        byte[] certificateEncoding;
        byte[] data;
        byte[] signature;

        {
            JcaTlsCrypto crypto = new JcaTlsCryptoProvider().setProvider("BC").create(new SecureRandom());

            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
            kpGen.initialize(new ECGenParameterSpec("sm2p256v1"), crypto.getSecureRandom());
            KeyPair keyPair = kpGen.generateKeyPair();

            TlsCertificate tlsCertificate = createJCACertificate(keyPair, crypto);
            certificateEncoding = tlsCertificate.getEncoded();
            Certificate tlsCertificateChain = new Certificate(new TlsCertificate[]{ tlsCertificate });

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv13);

            TlsCredentialedSigner signer = new JcaDefaultTlsCredentialedSigner(cryptoParams, crypto, keyPair.getPrivate(),
                tlsCertificateChain, SignatureAndHashAlgorithm.sm2sig_sm3);

            data = new byte[64];
            crypto.getSecureRandom().nextBytes(data);
    
            TlsStreamSigner streamSigner = signer.getStreamSigner();
            OutputStream signerOutput = streamSigner.getOutputStream();
            signerOutput.write(data);
            signerOutput.close();
            signature = streamSigner.getSignature();

            assertNotNull(signature);
            assertTrue("Signature should be non‑empty", signature.length > 0);
        }

        {
            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

            TlsCertificate tlsCertificate = crypto.createCertificate(certificateEncoding);

            Tls13Verifier verifier = tlsCertificate.createVerifier(SignatureScheme.sm2sig_sm3);
            OutputStream verifierOutput = verifier.getOutputStream();
            verifierOutput.write(data);
            verifierOutput.close();
            assertTrue(verifier.verifySignature(signature));
        }
    }

    public void testSM2SignerAndVerifier_JCA_JCA()
        throws Exception
    {
        byte[] certificateEncoding;
        byte[] data;
        byte[] signature;
        
        {
            JcaTlsCrypto crypto = new JcaTlsCryptoProvider().setProvider("BC").create(new SecureRandom());

            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
            kpGen.initialize(new ECGenParameterSpec("sm2p256v1"), crypto.getSecureRandom());
            KeyPair keyPair = kpGen.generateKeyPair();

            TlsCertificate tlsCertificate = createJCACertificate(keyPair, crypto);
            certificateEncoding = tlsCertificate.getEncoded();
            Certificate tlsCertificateChain = new Certificate(new TlsCertificate[]{ tlsCertificate });

            TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv13);

            TlsCredentialedSigner signer = new JcaDefaultTlsCredentialedSigner(cryptoParams, crypto, keyPair.getPrivate(),
                tlsCertificateChain, SignatureAndHashAlgorithm.sm2sig_sm3);

            data = new byte[64];
            crypto.getSecureRandom().nextBytes(data);
    
            TlsStreamSigner streamSigner = signer.getStreamSigner();
            OutputStream signerOutput = streamSigner.getOutputStream();
            signerOutput.write(data);
            signerOutput.close();
            signature = streamSigner.getSignature();

            assertNotNull(signature);
            assertTrue("Signature should be non‑empty", signature.length > 0);
        }

        {
            JcaTlsCrypto crypto = new JcaTlsCryptoProvider().setProvider("BC").create(new SecureRandom());

            TlsCertificate tlsCertificate = crypto.createCertificate(certificateEncoding);

            Tls13Verifier verifier = tlsCertificate.createVerifier(SignatureScheme.sm2sig_sm3);
            OutputStream verifierOutput = verifier.getOutputStream();
            verifierOutput.write(data);
            verifierOutput.close();
            assertTrue(verifier.verifySignature(signature));
        }
    }

    private AsymmetricCipherKeyPair generateSM2KeyPair(BcTlsCrypto crypto)
    {
        BcTlsECDomain ecDomain = new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.curveSM2));
        return ecDomain.generateKeyPair();
    }

    private BcTlsCertificate createBCCertificate(AsymmetricCipherKeyPair keyPair, BcTlsCrypto crypto)
        throws Exception
    {
        long now = System.currentTimeMillis();
        X500Name subject = new X500Name("CN=SM2 Test Certificate");
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)keyPair.getPublic();
        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey);
        BigInteger serial = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            subject, serial, new Date(now - 86400000L), new Date(now + 86400000L), subject, pubKeyInfo);

        BcX509ExtensionUtils extUtils = new BcX509ExtensionUtils();
        SubjectKeyIdentifier subjKeyId = extUtils.createSubjectKeyIdentifier(pubKeyInfo);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjKeyId);

        AuthorityKeyIdentifier authKeyId = extUtils.createAuthorityKeyIdentifier(pubKeyInfo);
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authKeyId);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SM3withSM2");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        BcECContentSignerBuilder signerBuilder = new BcECContentSignerBuilder(sigAlgId, digAlgId);
        ContentSigner signer = signerBuilder.build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);

        return new BcTlsCertificate(crypto, certHolder.toASN1Structure());
    }

    private JcaTlsCertificate createJCACertificate(KeyPair keyPair, JcaTlsCrypto crypto)
        throws Exception
    {
        return new JcaTlsCertificate(crypto, createSelfSignedCertificate(keyPair));
    }

    private X509Certificate createSelfSignedCertificate(KeyPair keyPair)
        throws Exception
    {
        long now = System.currentTimeMillis();
        X500Name subject = new X500Name("CN=SM2 JCA Test Certificate");
        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(now),
            new Date(now - 86400000L),
            new Date(now + 86400000L),
            subject,
            pubKeyInfo);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(pubKeyInfo));
        certBuilder.addExtension(Extension.basicConstraints, true,
            new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2")
            .setProvider("BC")
            .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    private static class TestTlsCryptoParameters
        extends TlsCryptoParameters
    {
        private final ProtocolVersion serverVersion;

        TestTlsCryptoParameters(ProtocolVersion serverVersion)
        {
            super(null);

            this.serverVersion = serverVersion;
        }

        public ProtocolVersion getServerVersion()
        {
            return serverVersion;
        }
    }
}
