package org.bouncycastle.cert.cmp.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import junit.framework.Assert;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

class TestUtils
{
    static X509CertificateHolder makeV3Certificate(String _subDN, KeyPair issKP)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub  = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_subDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            issKP.getPublic());

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withDSA").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        Assert.assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }

    static X509CertificateHolder makeV3Certificate(SubjectPublicKeyInfo pubKey, X500Name _subDN, KeyPair issKP, String _issDN)
        throws OperatorCreationException, CertException, CertIOException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            BigInteger.valueOf(System.currentTimeMillis()),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            _subDN,
            pubKey);

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withDSA").build(issPriv);

        X509CertificateHolder certHolder = certGen.build(signer);

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(issPub);

        Assert.assertTrue(certHolder.isSignatureValid(verifier));

        return certHolder;
    }
}
