package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class TestCertificateGen
{
    private static volatile long serialNumber = System.currentTimeMillis();
    private static Map<String, AlgorithmIdentifier> algIds = new HashMap<String, AlgorithmIdentifier>();

    static
    {
        algIds.put("GOST3411withGOST3410", new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94));
        algIds.put("SHA1withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("SHA256withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("SHA1withECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1));
        algIds.put("MD5WithRSAEncryption", new AlgorithmIdentifier(PKCSObjectIdentifiers.md5WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("LMS", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig));
        algIds.put("Ed448", new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448));
    }

    private synchronized static long getSerialNumber()
    {
        return serialNumber++;
    }

    public static X509Certificate createSelfSignedCert(String dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        return createSelfSignedCert(new X500Name(dn), sigName, keyPair);
    }

    public static X509Certificate createSelfSignedCert(X500Name dn, String sigName, KeyPair keyPair)
        throws Exception
    {
        V1TBSCertificateGenerator certGen = new V1TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(getSerialNumber()));
        certGen.setIssuer(dn);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(keyPair.getPrivate());

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    public static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, String dn, String sigName, Extensions extensions, PublicKey pubKey)
        throws Exception
    {
        return createCert(signerName, signerKey, new X500Name(dn), sigName, extensions, pubKey);
    }

    public static X509Certificate createCert(X500Name signerName, PrivateKey signerKey, X500Name dn, String sigName, Extensions extensions, PublicKey pubKey)
        throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(getSerialNumber()));
        certGen.setIssuer(signerName);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        certGen.setExtensions(extensions);

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(signerKey);

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    public static X509Certificate createCertWithIDs(X500Name signerName, String sigName, KeyPair keyPair, boolean[] subjectUniqID, boolean[] issuerUniqID)
        throws Exception
    {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        long time = System.currentTimeMillis();

        certGen.setSerialNumber(new ASN1Integer(getSerialNumber()));
        certGen.setIssuer(signerName);
        certGen.setSubject(signerName);
        certGen.setStartDate(new Time(new Date(time - 5000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 1000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        if (issuerUniqID != null)
        {
            certGen.setIssuerUniqueID(booleanToBitString(issuerUniqID));
        }

        if (subjectUniqID != null)
        {
            certGen.setSubjectUniqueID(booleanToBitString(subjectUniqID));
        }

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(keyPair.getPrivate());

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static X509Certificate generateRootCert(KeyPair pair)
        throws Exception
    {
        return createSelfSignedCert("CN=Test CA Certificate", "SHA256withRSA", pair);
    }

    public static X509Certificate generateRootCert(KeyPair pair, X500Name dn)
        throws Exception
    {
        return createSelfSignedCert(dn, "SHA256withRSA", pair);
    }

    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateIntermediateCert(
            intKey, new X500Name("CN=Test Intermediate Certificate"), caKey, caCert);
    }

    public static X509Certificate generateIntermediateCert(PublicKey intKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()),
            new GeneralNames(new GeneralName(caCertLw.getIssuer())),
            caCertLw.getSerialNumber().getValue()));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(intKey.getEncoded()))));
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return createCert(
            caCertLw.getSubject(),
            caKey, subject, "SHA256withRSA", extGen.generate(), intKey);
    }

    public static X509Certificate generateEndEntityCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        return generateEndEntityCert(
            intKey, new X500Name("CN=Test End Certificate"), caKey, caCert);
    }

    public static X509Certificate generateEndEntityCert(PublicKey entityKey, X500Name subject, PrivateKey caKey, X509Certificate caCert)
        throws Exception
    {
        Certificate caCertLw = Certificate.getInstance(caCert.getEncoded());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(getDigest(caCertLw.getSubjectPublicKeyInfo()),
            new GeneralNames(new GeneralName(caCertLw.getIssuer())),
            caCertLw.getSerialNumber().getValue()));
        extGen.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(getDigest(entityKey.getEncoded())));
        extGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return createCert(
            caCertLw.getSubject(),
            caKey, subject, "SHA256withRSA", extGen.generate(), entityKey);
    }

    public static X509CRL createCRL(
        X509Certificate caCert,
        PrivateKey caKey,
        BigInteger revokedSerialNumber)
        throws Exception
    {
        V2TBSCertListGenerator crlGen = new V2TBSCertListGenerator();
        Date now = new Date();

        X500Name issuer = new X500Name(caCert.getSubjectDN().getName());
        crlGen.setIssuer(issuer);

        crlGen.setThisUpdate(new Time(now));
        crlGen.setNextUpdate(new Time(new Date(now.getTime() + 100000)));
        crlGen.setSignature((AlgorithmIdentifier)algIds.get("SHA256withRSA"));

        crlGen.addCRLEntry(new ASN1Integer(revokedSerialNumber), new Time(now), CRLReason.privilegeWithdrawn);

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(issuer)), caCert.getSerialNumber()));
        extGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

        crlGen.setExtensions(extGen.generate());

        Signature sig = Signature.getInstance("SHA256withRSA", "BC");

        sig.initSign(caKey);

        sig.update(crlGen.generateTBSCertList().getEncoded(ASN1Encoding.DER));

        TBSCertList tbsCrl = crlGen.generateTBSCertList();

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCrl);
        v.add((AlgorithmIdentifier)algIds.get("SHA256withRSA"));
        v.add(new DERBitString(sig.sign()));

        return (X509CRL)CertificateFactory.getInstance("X.509", "BC").generateCRL(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki)
        throws IOException
    {
        return getDigest(spki.getPublicKeyData().getBytes());
    }

    private static byte[] getDigest(byte[] bytes)
    {
        try
        {
            return MessageDigest.getInstance("SHA1").digest(bytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            return null;
        }
    }

    private static DERBitString booleanToBitString(boolean[] id)
    {
        byte[] bytes = new byte[(id.length + 7) / 8];

        for (int i = 0; i != id.length; i++)
        {
            bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
        }

        int pad = id.length % 8;

        if (pad == 0)
        {
            return new DERBitString(bytes);
        }
        else
        {
            return new DERBitString(bytes, 8 - pad);
        }
    }
}
