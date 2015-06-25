package org.bouncycastle.cert.test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.test.SimpleTest;


/**
 * BC bug test case.
 */
public class CertPathLoopTest
    extends SimpleTest
{
    /**
     * List of trust anchors
     */
    private static Set<TrustAnchor> taSet;
    /**
     * List of certificates and CRLs
     */
    private static List<Object> otherList;

    /**
     * Asks the user about the configuration he want's to test
     *
     * @param caA
     * @param caB
     */
    private static void checkUseDistinctCAs(CA caA, CA caB)
    {
        //Standard configuration : everything in caA
        taSet = new HashSet<TrustAnchor>();
        taSet.add(caA.ta);
        otherList = new ArrayList<Object>();
        otherList.add(caA.acCertCrl);
        otherList.add(caA.crl);
        //User specified configuration : parts of caB

        taSet.add(caB.ta);
        otherList.add(caB.acCertCrl);
        otherList.add(caB.crl);
    }

    /**
     * Creates a collection cert store
     */
    static CertStore getStore(Collection col)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        CertStoreParameters csp = new CollectionCertStoreParameters(col);
        return CertStore.getInstance("Collection", csp);
    }

    public String getName()
    {
        return "CertPath Loop Test";
    }

    public void performTest()
        throws Exception
    {
              //Add the provider
        Security.addProvider(new BouncyCastleProvider());
        //Generate two Cert authorities
        CA caA = new CA();
        CA caB = new CA();
        //Ask the user the conf he want's to test
        checkUseDistinctCAs(caA, caB);

        //Let's create a target cert under caA
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(caA.makeNewCert());
        //create control parameters
        PKIXBuilderParameters params = new PKIXBuilderParameters(taSet, target);
        params.addCertStore(getStore(Collections.singleton(target.getCertificate())));
        params.addCertStore(getStore(otherList));
        //enable revocation check
        params.setRevocationEnabled(true);

        //Lets Build the path
        try
        {
            CertPathBuilderResult cpbr = CertPathBuilder.getInstance("PKIX", "BC").build(params);

            fail("invalid path build");
        }
        catch (CertPathBuilderException e)
        {
            if (!e.getCause().getMessage().equals("CertPath for CRL signer failed to validate."))
            {
                fail("Exception thrown, but wrong one", e.getCause());
            }
        }
    }

    /**
     * Class simulating a certification authority
     */
    private static class CA
    {
        /**
         * key pair generator
         */
        final static KeyPairGenerator kpg;

        static
        {
            try
            {
                kpg = KeyPairGenerator.getInstance("RSA");
                //Key size doesn't matter, smaller == Faster
                kpg.initialize(512);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException(e);
            }
        }

        /**
         * KeyPair signing certificates
         */
        private KeyPair caCertKp;
        /**
         * KeyPair signing CRLs
         */
        private KeyPair caCrlKp;
        TrustAnchor ta;
        /**
         * Subject of this CA
         */
        X500Name acSubject;
        /**
         * Certificate signing certificates
         */
        X509Certificate acCertAc;
        /**
         * Certificate signing CRLs
         */
        X509Certificate acCertCrl;
        /**
         * the CRL
         */
        X509CRL crl;
        /**
         * Signers
         */
        private ContentSigner caCrlSigner, caCertSigner;
        /**
         * Serial number counter
         */
        private int counter = 1;

        /**
         * Constructor
         */
        public CA()
            throws Exception
        {
            //Init both keypairs
            caCertKp = kpg.generateKeyPair();
            caCrlKp = kpg.generateKeyPair();
            //subject
            acSubject = new X500Name("CN=AC_0");
            //validity
            GregorianCalendar gc = new GregorianCalendar();
            Date notBefore = gc.getTime();
            gc.add(GregorianCalendar.DAY_OF_YEAR, 1);
            Date notAfter = gc.getTime();
            //first signer
            caCertSigner = new JcaContentSignerBuilder("SHA1withRSA").build(caCertKp.getPrivate());
            //top level : issuer is self
            X500Name issuer = acSubject;
            //reserved for future use (another test case)
            ContentSigner thisAcSigner = caCertSigner;
            //reserved for future use (another test case)
            //First certificate: Certificate authority (BasicConstraints=true) but not CRLSigner
            X509CertificateHolder certH = new X509v3CertificateBuilder(
                issuer, BigInteger.valueOf(counter++), notBefore, notAfter, acSubject, getPublicKeyInfo(caCertKp.getPublic()))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign))
                .build(thisAcSigner);
            //lets convert to X509Certificate
            acCertAc = convert(certH);
            //and build a trust Anchor
            ta = new TrustAnchor(acCertAc, null);

            //Second signer
            caCrlSigner = new JcaContentSignerBuilder("SHA1withRSA").build(caCrlKp.getPrivate());
            //second certificate: CRLSigner but not Certificate authority (BasicConstraints=false)
            certH = new X509v3CertificateBuilder(
                issuer, BigInteger.valueOf(counter++), notBefore, notAfter, acSubject, getPublicKeyInfo(caCrlKp.getPublic()))
                .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.cRLSign))
                .build(thisAcSigner);
            //lets convert to X509Certificate
            acCertCrl = convert(certH);
            //And create the CRL
            X509CRLHolder crlH = new X509v2CRLBuilder(acSubject, notBefore).setNextUpdate(notAfter).build(caCrlSigner);
            //lets convert to X509CRL
            crl = convert(crlH);
        }

        /**
         * Creates a child certificate
         */
        public X509Certificate makeNewCert()
            throws Exception
        {
            //private key doesn't matter for the test
            PublicKey publicKey = kpg.generateKeyPair().getPublic();
            //Validity
            GregorianCalendar gc = new GregorianCalendar();
            Date notBefore = gc.getTime();
            gc.add(GregorianCalendar.DAY_OF_YEAR, 1);
            Date notAfter = gc.getTime();
            //serial
            BigInteger certSerial = BigInteger.valueOf(counter++);
            //Distinct name based on the serial
            X500Name subject = new X500Name("CN=EU_" + certSerial.toString());
            //End user certificate, not allowed to do anything
            X509CertificateHolder enUserCertH = new X509v3CertificateBuilder(
                acSubject, certSerial, notBefore, notAfter, subject, getPublicKeyInfo(publicKey))
                .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(0))
                .build(caCertSigner);

            //lets convert to X509Certificate
            return convert(enUserCertH);
        }


        /**
         * convert to X509Certificate
         */
        static X509Certificate convert(X509CertificateHolder h)
            throws Exception
        {
            return new JcaX509CertificateConverter().getCertificate(h);
        }

        /**
         * convert to X509CRL
         */
        static X509CRL convert(X509CRLHolder h)
            throws Exception
        {
            return new JcaX509CRLConverter().getCRL(h);
        }

        /**
         * convert to SubjectPublicKeyInfo
         */
        static SubjectPublicKeyInfo getPublicKeyInfo(PublicKey k)
            throws Exception
        {
            return SubjectPublicKeyInfo.getInstance(k.getEncoded());
        }
    }

    public static void main(String[] args)
    {
        runTest(new CertPathLoopTest());
    }
}
