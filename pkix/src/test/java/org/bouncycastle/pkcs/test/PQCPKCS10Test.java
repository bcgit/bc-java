package org.bouncycastle.pkcs.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PrivateKeyPossessionStatement;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class PQCPKCS10Test
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testKEMPKCS10()
        throws Exception
    {
        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        dilKpGen.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair dilKp = dilKpGen.generateKeyPair();

        X509CertificateHolder sigCert = makeV3Certificate("CN=ML-KEM Client", dilKp);

        KeyPairGenerator kemKpGen = KeyPairGenerator.getInstance("ML-KEM", "BC");

        kemKpGen.initialize(MLKEMParameterSpec.ml_kem_768);

        KeyPair kemKp = kemKpGen.generateKeyPair();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                                                        new X500Name("CN=ML-KEM Client"), kemKp.getPublic());

        pkcs10Builder.addAttribute(X509AttributeIdentifiers.id_at_statementOfPossession,
                                        new PrivateKeyPossessionStatement(sigCert.toASN1Structure()));

        PKCS10CertificationRequest request = pkcs10Builder.build(
                            new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(dilKp.getPrivate()));

        assertTrue(request.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(sigCert.getSubjectPublicKeyInfo())));
    }

    private static X509CertificateHolder makeV3Certificate(String _subDN, KeyPair issKP)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() - 5000L),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            issKP.getPublic());

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }
}
