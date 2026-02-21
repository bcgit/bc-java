package org.bouncycastle.tls.test;

import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import junit.framework.TestCase;

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
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsECDomain;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsRawKeyCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Test for TLS 1.3 with ShangMi (SM) cipher suites as defined in RFC 8998.
 */
public class SM2Tls13Test
    extends TestCase
{
    private static final byte[] HANDSHAKE_ID = "TLSv1.3+GM+Cipher+Suite".getBytes();

    public static void main(String[] args)
        throws Exception
    {
        SM2Tls13Test t = new SM2Tls13Test();
        t.setUp();
        t.testBcSM2SignerAndVerifier();
        t.testJcaSM2SignerAndVerifier();
    }

    protected void setUp()
        throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testBcSM2SignerAndVerifier()
        throws Exception
    {
        BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

        AsymmetricCipherKeyPair keyPair = generateSM2KeyPair(crypto);
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.getPublic();

        TlsCertificate tlsCert = createCertificate(keyPair, crypto);
        Certificate certChain = new Certificate(new TlsCertificate[]{tlsCert});

        SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
        BcTlsRawKeyCertificate rawCert = new BcTlsRawKeyCertificate(crypto, pubKeyInfo);

        SignatureAndHashAlgorithm sigAlg = SignatureAndHashAlgorithm.sm2sig_sm3;

        TlsContext dummyContext = new DummyTlsContext(crypto);
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(dummyContext);

        BcDefaultTlsCredentialedSigner signer = new BcDefaultTlsCredentialedSigner(
            cryptoParams, crypto, privateKey, certChain, sigAlg);

        byte[] hash = new byte[32];
        crypto.getSecureRandom().nextBytes(hash);

        byte[] signature = signer.generateRawSignature(hash);
        assertNotNull(signature);
        assertTrue("Signature should be non‑empty", signature.length > 0);

        Tls13Verifier verifier = rawCert.createVerifier(SignatureScheme.sm2sig_sm3);
        OutputStream output = verifier.getOutputStream();
        output.write(hash);
        assertTrue(verifier.verifySignature(signature));

        SM2Signer directVerifier = new SM2Signer(PlainDSAEncoding.INSTANCE);
        ParametersWithID params = new ParametersWithID(publicKey, HANDSHAKE_ID);
        directVerifier.init(false, params);
        directVerifier.update(hash, 0, hash.length);
        assertTrue("Direct verification failed", directVerifier.verifySignature(signature));
    }

    private AsymmetricCipherKeyPair generateSM2KeyPair(TlsCrypto crypto)
    {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        ECDomainParameters domainParams = BcTlsECDomain.getDomainParameters(NamedGroup.curveSM2);
        gen.init(new ECKeyGenerationParameters(domainParams, crypto.getSecureRandom()));
        return gen.generateKeyPair();
    }

    private TlsCertificate createCertificate(AsymmetricCipherKeyPair keyPair, BcTlsCrypto crypto)
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

        return new BcTlsCertificate(crypto, certHolder.getEncoded());
    }

    public void testJcaSM2SignerAndVerifier()
        throws Exception
    {
        JcaTlsCrypto crypto = new JcaTlsCryptoProvider().create(new SecureRandom());

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        kpGen.initialize(new ECGenParameterSpec("sm2p256v1"), crypto.getSecureRandom());
        KeyPair keyPair = kpGen.generateKeyPair();

        X509Certificate certificate = createSelfSignedCertificate(keyPair);
        Certificate tlsCertificateChain = new Certificate(new TlsCertificate[]{
            new JcaTlsCertificate(crypto, certificate)
        });

        TlsContext dummyContext = new DummyTlsContext(crypto);
        TlsCryptoParameters cryptoParams = new TlsCryptoParameters(dummyContext);

        SignatureAndHashAlgorithm sigAlg = SignatureAndHashAlgorithm.sm2sig_sm3;

        TlsCredentialedSigner signer = new JcaDefaultTlsCredentialedSigner(
            cryptoParams, crypto, keyPair.getPrivate(), tlsCertificateChain, sigAlg);

        byte[] hash = new byte[32];
        crypto.getSecureRandom().nextBytes(hash);

        byte[] signature = signer.generateRawSignature(hash);
        assertNotNull(signature);
        assertTrue(signature.length > 0);

        JcaTlsCertificate tlsCert = new JcaTlsCertificate(crypto, certificate);
        org.bouncycastle.tls.crypto.Tls13Verifier verifier = tlsCert.createVerifier(SignatureScheme.sm2sig_sm3);
        OutputStream output = verifier.getOutputStream();
        output.write(hash);
        assertTrue(verifier.verifySignature(signature));

        Signature jcaVerifier = Signature.getInstance("SM3withSM2", "BC");
        SM2ParameterSpec paramSpec = new SM2ParameterSpec(HANDSHAKE_ID);
        jcaVerifier.setParameter(paramSpec);
        jcaVerifier.initVerify(keyPair.getPublic());
        jcaVerifier.update(hash);
        assertTrue("JCA direct verification failed", jcaVerifier.verify(signature));
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

    private static class DummyTlsContext
        implements TlsContext
    {
        private final TlsCrypto crypto;

        DummyTlsContext(TlsCrypto crypto)
        {
            this.crypto = crypto;
        }

        @Override
        public TlsCrypto getCrypto()
        {
            return crypto;
        }

        @Override
        public SecurityParameters getSecurityParametersHandshake()
        {
            return null;
        }

        @Override
        public SecurityParameters getSecurityParametersConnection()
        {
            return null;
        }

        @Override
        public ProtocolVersion getClientVersion()
        {
            return ProtocolVersion.TLSv13;
        }

        @Override
        public ProtocolVersion getServerVersion()
        {
            return ProtocolVersion.TLSv13;
        }

        @Override
        public TlsSession getResumableSession()
        {
            return null;
        }

        @Override
        public ProtocolVersion getRSAPreMasterSecretVersion()
        {
            return null;
        }

        @Override
        public TlsSession getSession()
        {
            return null;
        }

        @Override
        public boolean isServer()
        {
            return false;
        }

        @Override
        public ProtocolVersion[] getClientSupportedVersions()
        {
            return new ProtocolVersion[0];
        }

        @Override
        public Object getUserObject()
        {
            return null;
        }

        @Override
        public void setUserObject(Object userObject)
        {
        }

        @Override
        public byte[] exportChannelBinding(int channelBinding)
        {
            return null;
        }

        @Override
        public byte[] exportEarlyKeyingMaterial(String asciiLabel, byte[] context, int length)
        {
            return null;
        }

        @Override
        public byte[] exportKeyingMaterial(String asciiLabel, byte[] context, int length)
        {
            return null;
        }

        @Override
        public TlsNonceGenerator getNonceGenerator()
        {
            return crypto.createNonceGenerator(new byte[0]);
        }

        @Override
        public SecurityParameters getSecurityParameters()
        {
            return null;
        }
    }
}