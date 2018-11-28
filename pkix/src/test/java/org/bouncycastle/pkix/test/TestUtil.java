package org.bouncycastle.pkix.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TestUtil
{
    public static BigInteger       serialNumber = BigInteger.ONE;

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return _tmp;
    }

    public static X509Certificate makeTrustAnchor(KeyPair kp, String name)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
            new X500Name(name),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(name),
            kp.getPublic());

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC");

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(v1CertGen.build(contentSignerBuilder.build(kp.getPrivate())));

        cert.checkValidity(new Date());
        cert.verify(kp.getPublic());

        return cert;
    }

    public static X509Certificate makeCaCertificate(X509Certificate issuer, PrivateKey issuerKey, PublicKey subjectKey, String subject)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            issuer.getSubjectX500Principal(),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Principal(subject),
            subjectKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(subjectKey));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(issuer));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(0));

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC");

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issuerKey)));

        cert.checkValidity(new Date());
        cert.verify(issuer.getPublicKey());

        return cert;
    }

    public static X509Certificate makeEeCertificate(boolean withDistPoint, X509Certificate issuer, PrivateKey issuerKey, PublicKey subjectKey, String subject)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            issuer.getSubjectX500Principal(),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Principal(subject),
            subjectKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(subjectKey));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            extUtils.createAuthorityKeyIdentifier(issuer));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(false));

        if (withDistPoint)
        {
            v3CertGen.addExtension(
                Extension.cRLDistributionPoints,
                false,
                new DERSequence());
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC");

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issuerKey)));

        cert.checkValidity(new Date());
        cert.verify(issuer.getPublicKey());

        return cert;
    }

    public static X509CRL makeCrl(X509Certificate issuer, PrivateKey sigKey, BigInteger revoked)
        throws Exception
    {
        Date now = new Date();
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(issuer.getSubjectX500Principal(), now);
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRLEntry(revoked, now, CRLReason.privilegeWithdrawn);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(issuer));

        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlGen.build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(sigKey)));
    }
}
