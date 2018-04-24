package org.bouncycastle.test.est.examples;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * A Collection of utility functions for reading and handling certificates and private keys.
 * Copied directly from ESTTestUtils.
 */
public class ExampleUtils
{

    private static Map algIds = new HashMap();

    static
    {
        algIds.put("GOST3411withGOST3410", new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94));
        algIds.put("SHA1withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("SHA256withRSA", new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
        algIds.put("ECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa_with_sha1));
        algIds.put("SHA256WITHECDSA", new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256));
    }


    public static void ensureProvider()
    {
        Provider[] pp = Security.getProviders();
        for (Provider p : pp)
        {
            if (p.getName().equals("BC"))
            {
                return;
            }
        }
        Security.addProvider(new BouncyCastleProvider());

        for (Provider p : pp)
        {
            if (p.getName().equals("BCJSSE"))
            {
                return;
            }
        }
        Security.addProvider(new BouncyCastleJsseProvider());

    }

    /**
     * Convert (X509CertificateHolder, X509Certificate, javax X509Certificate) to trust anchors.
     * Constraints are set null.
     *
     * @param oo
     * @return
     * @throws Exception
     */
    public static Set<TrustAnchor> toTrustAnchor(Object... oo)
        throws Exception
    {
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        HashSet<TrustAnchor> out = new HashSet<TrustAnchor>();
        for (Object o : oo)
        {
            if (o instanceof X509CertificateHolder)
            {
                out.add(new TrustAnchor((java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(((X509CertificateHolder)o).getEncoded())), null));
            }
            else if (o instanceof X509Certificate)
            {
                out.add(new TrustAnchor((java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(((X509Certificate)o).getEncoded())), null));
            }
            else if (o instanceof java.security.cert.X509Certificate)
            {
                out.add(new TrustAnchor((java.security.cert.X509Certificate)o, null));
            }
            else if (o instanceof TrustAnchor)
            {
                out.add((TrustAnchor)o);
            }
            else
            {
                throw new IllegalArgumentException("Could not convert " + o.getClass().getName() + " to X509Certificate");
            }
        }

        return out;
    }

    public static List<java.security.cert.X509Certificate> toCertList(X509Certificate[] certs)
        throws Exception
    {
        CertificateFactory fac = CertificateFactory.getInstance("X509");

        ArrayList<java.security.cert.X509Certificate> c = new ArrayList<java.security.cert.X509Certificate>();
        for (X509Certificate cc : certs)
        {
            c.add((java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(cc.getEncoded())));
        }
        return c;
    }


    public static List<java.security.cert.X509Certificate> toCertList(Object[] certs)
        throws Exception
    {
        CertificateFactory fac = CertificateFactory.getInstance("X509");

        ArrayList<java.security.cert.X509Certificate> c = new ArrayList<java.security.cert.X509Certificate>();
        for (Object cc : certs)
        {
            c.add(toJavaX509Certificate(cc));
        }
        return c;
    }


    public static java.security.cert.X509Certificate toJavaX509Certificate(Object o)
        throws Exception
    {
        CertificateFactory fac = CertificateFactory.getInstance("X509");
        if (o instanceof X509CertificateHolder)
        {
            return (java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(((X509CertificateHolder)o).getEncoded()));
        }
        else if (o instanceof X509Certificate)
        {
            return (java.security.cert.X509Certificate)fac.generateCertificate(new ByteArrayInputStream(((X509Certificate)o).getEncoded()));
        }
        else if (o instanceof java.security.cert.X509Certificate)
        {
            return (java.security.cert.X509Certificate)o;
        }
        throw new IllegalArgumentException("Object not X509CertificateHolder, javax..X509Certificate or java...X509Certificate");
    }


    /**
     * @param sigName              signing algorithm
     * @param subjectDN            Subject of the certificate.
     * @param subjectPublicKeyInfo Public key of the subject.
     * @param issuerDN             Issuer of the certificate.
     * @param issuerPrivateKey     The issuer private key.
     * @param serialNumber         Serial number.
     * @return A (java) X509Certificate.
     * @throws Exception
     */
    public static java.security.cert.X509Certificate createASignedCert(
        String sigName,
        X500Name subjectDN,
        SubjectPublicKeyInfo subjectPublicKeyInfo,
        X500Name issuerDN,
        PrivateKey issuerPrivateKey,
        long serialNumber,
        ASN1EncodableVector purposes,
        KeyUsage usage
    )
        throws Exception
    {

        // SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        long time = System.currentTimeMillis();

        ExtensionsGenerator extGenerator = new ExtensionsGenerator();

        if (usage != null)
        {
            extGenerator.addExtension(Extension.keyUsage, false, usage);
        }

        if (purposes != null)
        {
            extGenerator.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        }


        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        certGen.setSerialNumber(new ASN1Integer(serialNumber));
        certGen.setIssuer(issuerDN);
        certGen.setSubject(subjectDN);
        certGen.setStartDate(new Time(new Date(time - 24 * 60 * 60000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 60000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        certGen.setExtensions(extGenerator.generate());


        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(issuerPrivateKey);

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (java.security.cert.X509Certificate)
            CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(
                    new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)
                    ));
    }


    /**
     * @param sigName              signing algorithm
     * @param subjectDN            Subject of the certificate.
     * @param subjectPublicKeyInfo Public key of the subject.
     * @param issuerPrivateKey     The issuer private key.
     * @param serialNumber         Serial number.
     * @return A (java) X509Certificate.
     * @throws Exception
     */
    public static java.security.cert.X509Certificate createSelfsignedCert(
        String sigName,
        X500Name subjectDN,
        SubjectPublicKeyInfo subjectPublicKeyInfo,
        PrivateKey issuerPrivateKey,
        long serialNumber

    )
        throws Exception
    {

        // SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

        long time = System.currentTimeMillis();


        V1TBSCertificateGenerator certGen = new V1TBSCertificateGenerator();

        certGen.setSerialNumber(new ASN1Integer(serialNumber));
        certGen.setIssuer(subjectDN);
        certGen.setSubject(subjectDN);
        certGen.setStartDate(new Time(new Date(time - 24 * 60 * 60000)));
        certGen.setEndDate(new Time(new Date(time + 30 * 60 * 60000)));
        certGen.setSignature((AlgorithmIdentifier)algIds.get(sigName));
        certGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);


        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(issuerPrivateKey);

        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add((AlgorithmIdentifier)algIds.get(sigName));
        v.add(new DERBitString(sig.sign()));

        return (java.security.cert.X509Certificate)
            CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(
                    new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)
                    ));
    }


    public static PrivateKey readPemPrivateKeyPKCS8DER(File path, String alg)
        throws Exception
    {

        int l = (int)path.length();

        byte[] der = new byte[l];
        DataInputStream din = new DataInputStream(new FileInputStream(path));
        din.readFully(der);
        din.close();

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(der);

        KeyFactory kf = KeyFactory.getInstance(alg, "BC");
        return kf.generatePrivate(ks);
    }


    public static PrivateKey readPemPrivateKey(File path, String alg)
        throws Exception
    {

        FileReader fr = new FileReader(path);
        PemReader reader = new PemReader(fr);
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(reader.readPemObject().getContent());
        reader.close();


        KeyFactory kf = KeyFactory.getInstance(alg, "BC");
        return kf.generatePrivate(ks);
    }


//    public static X509CertificateHolder readPemCertificate(File path)
//        throws Exception
//    {
//        FileReader fr = new FileReader(path);
//        PemReader reader = new PemReader(fr);
//        X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
//        reader.close();
//        fr.close();
//        return fromFile;
//    }

    public static Object[] readPemCertificates(File path)
        throws Exception
    {
        ArrayList<Object> certs = new ArrayList<Object>();
        FileReader fr = new FileReader(path);
        PemReader reader = new PemReader(fr);
        PemObject o;

        while ((o = reader.readPemObject()) != null)
        {
            certs.add(new X509CertificateHolder(o.getContent()));
        }
        reader.close();
        fr.close();
        return certs.toArray(new Object[certs.size()]);
    }


    public static String readToString(File f)
        throws IOException
    {
        StringWriter sw = new StringWriter();
        FileReader fr = new FileReader(f);
        char[] b = new char[8192];
        int i;
        while ((i = fr.read(b)) > -1)
        {
            sw.write(b, 0, i);
        }
        fr.close();
        sw.close();
        return sw.toString();
    }


    public static String toPem(X509CertificateHolder holder)
        throws Exception
    {
        StringWriter pemOut = new StringWriter();
        PemWriter pw = new PemWriter(pemOut);
        pw.writeObject(new MiscPEMGenerator(holder));
        pw.flush();
        return pemOut.toString();
    }

    static int nextArgAsInteger(String label, String[] args, int t)
    {
        if (t + 1 >= args.length || args[t + 1].startsWith("-"))
        {
            throw new IllegalArgumentException(label + ": Missing Integer argument");
        }

        return new Integer(args[t + 1]);
    }


    static File nextArgAsFile(String label, String[] args, int t)
    {
        if (t + 1 >= args.length || args[t + 1].startsWith("-"))
        {
            throw new IllegalArgumentException(label + ": Missing File argument");
        }

        return new File(args[t + 1]);
    }

    static String nextArgAsString(String label, String[] args, int t)
    {
        if (t + 1 >= args.length || args[t + 1].startsWith("-"))
        {
            throw new IllegalArgumentException(label + ": Missing File argument");
        }

        return args[t + 1];
    }

    static boolean userSaysYes(String question)
        throws IOException
    {
        BufferedReader bin = new BufferedReader(new InputStreamReader(System.in));
        String line;
        System.out.println();
        System.out.println(question + " ");
        while ((line = bin.readLine()) != null)
        {
            if (Strings.toLowerCase(line).startsWith("y"))
            {
                System.out.println();
                return true;
            }
            else if (Strings.toLowerCase(line).startsWith("n"))
            {
                break;
            }
            System.out.println();
            System.out.println(question + " ");
        }
        System.out.println();
        return false;
    }
}
