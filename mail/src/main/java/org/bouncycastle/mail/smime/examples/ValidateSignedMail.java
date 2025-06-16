package org.bouncycastle.mail.smime.examples;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;

/**
 * An Example that reads a signed mail and validates its signature. Also
 * validating the certificate path from the signers key to a trusted entity
 */
public class ValidateSignedMail
{

    /*
     * Use trusted certificates from $JAVA_HOME/lib/security/cacerts as
     * trustanchors
     */
    public static final boolean useCaCerts = false;

    public static void main(String[] args) throws Exception
    {

        Security.addProvider(new BouncyCastleProvider());

        //
        // Get a Session object with the default properties.
        //
        Properties props = System.getProperties();

        Session session = Session.getDefaultInstance(props, null);

        // read message
        MimeMessage msg = new MimeMessage(session, new FileInputStream(
                "signed.message"));

        // create PKIXparameters
        PKIXParameters param;

        if (useCaCerts)
        {
            KeyStore caCerts = KeyStore.getInstance("JKS");
            String javaHome = System.getProperty("java.home");
            caCerts.load(
                    new FileInputStream(javaHome + "/lib/security/cacerts"),
                    "changeit".toCharArray());

            param = new PKIXParameters(caCerts);
        }
        else
        {
            // load trustanchors from files (here we only load one)
            Set trustanchors = new HashSet();
            TrustAnchor trust = getTrustAnchor("trustanchor");

            // create a dummy trustanchor if we can not find any trustanchor. so
            // we can still try to validate the message
            if (trust == null)
            {
                System.out
                        .println("no trustanchor file found, using a dummy trustanchor");
                trust = getDummyTrustAnchor();
            }
            trustanchors.add(trust);

            param = new PKIXParameters(trustanchors);
        }

        // load one ore more crls from files (here we only load one crl)
        List crls = new ArrayList();
        X509CRL crl = loadCRL("crl.file");
        if (crl != null)
        {
            crls.add(crl);
        }
        CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(crls), "BC");

        // add crls and enable revocation checking
        param.addCertStore(certStore);
        param.setRevocationEnabled(true);

        // or disable revocation checking
        // param.setRevocationEnabled(false);

        verifySignedMail(msg, param);
    }

    public static final int TITLE = 0;
    public static final int TEXT = 1;
    public static final int SUMMARY = 2;
    public static final int DETAIL = 3;

    static int dbgLvl = DETAIL;

    private static final String RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";

    public static void verifySignedMail(MimeMessage msg, PKIXParameters param)
            throws Exception
    {
        // set locale for the output
        Locale loc = Locale.ENGLISH;
        // Locale loc = Locale.GERMAN;

        // validate signatures
        SignedMailValidator validator = new SignedMailValidator(msg, param);

        // iterate over all signatures and print results
        for (SignerInformation signer : validator.getSignerInformationStore().getSigners())
        {
            SignedMailValidator.ValidationResult result = validator
                    .getValidationResult(signer);
            if (result.isValidSignature())
            {
                ErrorBundle errMsg = new ErrorBundle(RESOURCE_NAME,
                        "SignedMailValidator.sigValid");
                errMsg.setClassLoader(SignedMailValidator.class.getClassLoader());
                System.out.println(errMsg.getText(loc));
            }
            else
            {
                ErrorBundle errMsg = new ErrorBundle(RESOURCE_NAME,
                        "SignedMailValidator.sigInvalid");
                errMsg.setClassLoader(SignedMailValidator.class.getClassLoader());
                System.out.println(errMsg.getText(loc));
                // print errors
                System.out.println("Errors:");
                for (Object o : result.getErrors()) {
                    ErrorBundle errorMsg = (ErrorBundle)o;
                    if (dbgLvl == DETAIL)
                    {
                        System.out.println("\t\t" + errorMsg.getDetail(loc));
                    }
                    else
                    {
                        System.out.println("\t\t" + errorMsg.getText(loc));
                    }
                }
            }
            if (!result.getNotifications().isEmpty())
            {
                System.out.println("Notifications:");
                for (Object o : result.getNotifications())
                {
                    ErrorBundle notMsg = (ErrorBundle)o;
                    if (dbgLvl == DETAIL)
                    {
                        System.out.println("\t\t" + notMsg.getDetail(loc));
                    }
                    else
                    {
                        System.out.println("\t\t" + notMsg.getText(loc));
                    }
                }
            }
            PKIXCertPathReviewer review = result.getCertPathReview();
            if (review != null)
            {
                if (review.isValidCertPath())
                {
                    System.out.println("Certificate path valid");
                }
                else
                {
                    System.out.println("Certificate path invalid");
                }

                System.out.println("\nCertificate path validation results:");
                // global errors
                System.out.println("Errors:");
                for (Object object : review.getErrors(-1))
                {
                    ErrorBundle errorMsg = (ErrorBundle)object;
                    if (dbgLvl == DETAIL)
                    {
                        System.out.println("\t\t" + errorMsg.getDetail(loc));
                    }
                    else
                    {
                        System.out.println("\t\t" + errorMsg.getText(loc));
                    }
                }

                System.out.println("Notifications:");
                for (Object o : review.getNotifications(-1))
                {
                    ErrorBundle noteMsg = (ErrorBundle)o;
                    System.out.println("\t" + noteMsg.getText(loc));
                }

                // per certificate errors and notifications
                int i = 0;
                for (java.security.cert.Certificate certificate : review.getCertPath().getCertificates())
                {
                    X509Certificate cert = (X509Certificate)certificate;
                    System.out.println("\nCertificate " + i + "\n========");
                    System.out.println("Issuer: "
                            + cert.getIssuerDN().getName());
                    System.out.println("Subject: "
                            + cert.getSubjectDN().getName());

                    // errors
                    System.out.println("\tErrors:");
                    for (Object object : review.getErrors(i))
                    {
                        ErrorBundle errorMsg = (ErrorBundle)object;
                        if (dbgLvl == DETAIL)
                        {
                            System.out
                                    .println("\t\t" + errorMsg.getDetail(loc));
                        }
                        else
                        {
                            System.out.println("\t\t" + errorMsg.getText(loc));
                        }
                    }

                    // notifications
                    System.out.println("\tNotifications:");
                    for (Object o : review.getNotifications(i))
                    {
                        ErrorBundle noteMsg = (ErrorBundle)o;
                        if (dbgLvl == DETAIL)
                        {
                            System.out.println("\t\t" + noteMsg.getDetail(loc));
                        }
                        else
                        {
                            System.out.println("\t\t" + noteMsg.getText(loc));
                        }
                    }

                    i++;
                }
            }
        }

    }

    protected static TrustAnchor getTrustAnchor(String trustcert)
            throws Exception
    {
        X509Certificate cert = loadCert(trustcert);
        if (cert != null)
        {
            byte[] ncBytes = cert
                    .getExtensionValue(Extension.nameConstraints.getId());

            if (ncBytes != null)
            {
                ASN1Encodable extValue = JcaX509ExtensionUtils
                        .parseExtensionValue(ncBytes);
                return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
            return new TrustAnchor(cert, null);
        }
        return null;
    }

    protected static X509Certificate loadCert(String certfile)
    {
        X509Certificate cert = null;
        try
        {
            InputStream in = new FileInputStream(certfile);

            CertificateFactory cf = CertificateFactory.getInstance("X.509",
                    "BC");
            cert = (X509Certificate) cf.generateCertificate(in);
        }
        catch (Exception e)
        {
            System.out.println("certfile \"" + certfile
                    + "\" not found - classpath is "
                    + System.getProperty("java.class.path"));
        }
        return cert;
    }

    protected static X509CRL loadCRL(String crlfile)
    {
        X509CRL crl = null;
        try
        {
            InputStream in = new FileInputStream(crlfile);

            CertificateFactory cf = CertificateFactory.getInstance("X.509",
                    "BC");
            crl = (X509CRL) cf.generateCRL(in);
        }
        catch (Exception e)
        {
            System.out.println("crlfile \"" + crlfile
                    + "\" not found - classpath is "
                    + System.getProperty("java.class.path"));
        }
        return crl;
    }

    private static TrustAnchor getDummyTrustAnchor() throws Exception
    {
        X500Principal principal = new X500Principal("CN=Dummy Trust Anchor");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024, new SecureRandom());
        PublicKey trustPubKey = kpg.generateKeyPair().getPublic();
        return new TrustAnchor(principal, trustPubKey, null);
    }

}
