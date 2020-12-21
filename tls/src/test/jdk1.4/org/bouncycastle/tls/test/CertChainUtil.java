package org.bouncycastle.tls.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertChainUtil
{
    public static String BC = "BC";

    private static final AtomicLong serialNumber = new AtomicLong(1);

    /*
     * we generate the CA's certificate
     */
    public static X509Certificate createMasterCert(
        String masterDN,
        KeyPair keyPair)
        throws Exception
    {
        //
        // create the certificate - version 1
        //
        X509v1CertificateBuilder v1CertBuilder = new JcaX509v1CertificateBuilder(
            new X500Name(masterDN),
            BigInteger.valueOf(serialNumber.getAndIncrement()),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            new X500Name(masterDN),
            keyPair.getPublic());

        X509CertificateHolder cert = v1CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(keyPair.getPrivate()));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    /*
     * we generate an intermediate certificate signed by our CA
     */
    public static X509Certificate createIntermediateCert(
        String interDN,
        PublicKey pubKey,
        PrivateKey rootPrivKey,
        X509Certificate rootCert)
        throws Exception
    {
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
            JcaX500NameUtil.getIssuer(rootCert),
            BigInteger.valueOf(serialNumber.getAndIncrement()),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            new X500Name(interDN),
            pubKey);


        //
        // extensions
        //
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        v3CertBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            utils.createSubjectKeyIdentifier(pubKey));

        v3CertBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            utils.createAuthorityKeyIdentifier(rootCert));

        v3CertBuilder.addExtension(
            Extension.basicConstraints,
            true,
            new BasicConstraints(0));

        X509CertificateHolder cert = v3CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(rootPrivKey));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    /*
     * we generate a certificate signed by our CA's intermediate certificate
     */
    public static X509Certificate createEndEntityCert(
        String endEntityDN,
        PublicKey pubKey,
        PrivateKey caPrivKey,
        X509Certificate caCert)
        throws Exception
    {
        X509v3CertificateBuilder v3CertBuilder = createBaseEndEntityBuilder(endEntityDN, pubKey, caCert);

        X509CertificateHolder cert = v3CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(caPrivKey));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    /*
     * we generate a certificate signed by our CA's intermediate certificate with ExtendedKeyUsage extension
     */
    public static X509Certificate createEndEntityCert(
        String endEntityDN,
        PublicKey pubKey,
        PrivateKey caPrivKey,
        X509Certificate caCert,
        KeyPurposeId keyPurposeId)
        throws Exception
    {
        X509v3CertificateBuilder v3CertBuilder = createBaseEndEntityBuilder(endEntityDN, pubKey, caCert);

        v3CertBuilder.addExtension(
            Extension.extendedKeyUsage,
            true,
            new ExtendedKeyUsage(keyPurposeId));

        X509CertificateHolder cert = v3CertBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(caPrivKey));

        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(cert);
    }

    private static X509v3CertificateBuilder createBaseEndEntityBuilder(String endEntityDN, PublicKey pubKey, X509Certificate caCert)
        throws IOException, NoSuchAlgorithmException
    {
        //
        // create the certificate - version 3
        //
        X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
            caCert.getIssuerX500Principal(),
            BigInteger.valueOf(serialNumber.getAndIncrement()),
            new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)),
            new X500Principal(new X500Name(endEntityDN).getEncoded()),
            pubKey);


        //
        // add the extensions
        //
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        v3CertBuilder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            utils.createSubjectKeyIdentifier(pubKey));

        v3CertBuilder.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            utils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        v3CertBuilder.addExtension(
            Extension.basicConstraints,
            true,
            new BasicConstraints(false));

        return v3CertBuilder;
    }
}
