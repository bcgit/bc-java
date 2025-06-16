package org.bouncycastle.mail.smime.examples;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESignedParser;
import org.bouncycastle.mail.smime.util.SharedFileInputStream;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

/**
 * a simple example that reads a basic SMIME signed mail file.
 */
public class ReadLargeSignedMail
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * verify the signature (assuming the cert is contained in the message)
     */
    private static void verify(
        SMIMESignedParser s)
        throws Exception
    {
        //
        // extract the information to verify the signatures.
        //

        //
        // certificates and crls passed in the signature - this must happen before
        // s.getSignerInfos()
        //
        Store certs = s.getCertificates();

        //
        // SignerInfo blocks which contain the signatures
        //
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();

        //
        // check each signer
        //
        for (Object o : c)
        {
            SignerInformation   signer = (SignerInformation)o;
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate((X509CertificateHolder)certIt.next());


            //
            // verify that the sig is correct and that it was generated
            // when the certificate was current
            //
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)))
            {
                System.out.println("signature verified");
            }
            else
            {
                System.out.println("signature failed!");
            }
        }
    }

    public static void main(
        String[]    args)
        throws Exception
    {
        //
        // Get a Session object with the default properties.
        //         
        Properties props = System.getProperties();

        Session session = Session.getDefaultInstance(props, null);

        MimeMessage msg = new MimeMessage(session, new SharedFileInputStream("signed.message"));

        //
        // make sure this was a multipart/signed message - there should be
        // two parts as we have one part for the content that was signed and
        // one part for the actual signature.
        //
        if (msg.isMimeType("multipart/signed"))
        {
            SMIMESignedParser             s = new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().build(),
                                            (MimeMultipart)msg.getContent());

            System.out.println("Status:");

            verify(s);
        }
        else if (msg.isMimeType("application/pkcs7-mime"))
        {
            //
            // in this case the content is wrapped in the signature block.
            //
            SMIMESignedParser       s = new SMIMESignedParser(new JcaDigestCalculatorProviderBuilder().build(), msg);

            System.out.println("Status:");

            verify(s);
        }
        else
        {
            System.err.println("Not a signed message!");
        }
    }
}
