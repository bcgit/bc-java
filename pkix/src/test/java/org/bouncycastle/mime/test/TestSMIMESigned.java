package org.bouncycastle.mime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.TestCase;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMIMESignedWriter;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class TestSMIMESigned
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private static String _signDN;
    private static KeyPair _signKP;

    private static String _reciDN;
    private static KeyPair _reciKP;

    private static X509Certificate _signCert;
    private static X509Certificate _reciCert;

    private static boolean _initialised = false;

    private static final byte[] simpleMessage = Strings.toByteArray(
        "Content-Type: text/plain; name=null; charset=us-ascii\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n" +
            "Content-Disposition: inline; filename=null\r\n" +
            "\r\n" +
            "Hello, world!\r\n");

    private static final byte[] simpleMessageContent = Strings.toByteArray(
            "Hello, world!\r\n");

    private static final byte[] testMultipartMessage = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
            "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
            "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
            "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
            "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
            "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
            "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
            "wMTMyLS0NCg==");

    private static final byte[] testMultipartMessageContent = Base64.decode(
        "LS0tLS0tPV9QYXJ0XzBfMjYwMzk2Mzg2LjEzNTI5MDQ3NTAxMzINCkNvbnRlbnQtVHlwZTogdGV4dC9w" +
            "bGFpbjsgbmFtZT1udWxsOyBjaGFyc2V0PXVzLWFzY2lpDQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5n" +
            "OiA3Yml0DQpDb250ZW50LURpc3Bvc2l0aW9uOiBpbmxpbmU7IGZpbGVuYW1lPW51bGwNCg0KQ2lhbyBm" +
            "cm9tIHZpZW5uYQ0KLS0tLS0tPV9QYXJ0XzBfMjYwMzk2Mzg2LjEzNTI5MDQ3NTAxMzItLQ0K");

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            if (Security.getProvider("BC") == null)
            {
                Security.addProvider(new BouncyCastleProvider());
            }

            _initialised = true;

            _signDN = "O=Bouncy Castle, C=AU";
            _signKP = CMSTestUtil.makeKeyPair();
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _reciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
        }
    }

    public void setUp()
        throws Exception
    {
        init();
    }

    public void testSimpleGeneration()
        throws Exception
    {
        generationTest(simpleMessage, simpleMessageContent);
    }

    public void testEmbeddedMultipartGeneration()
        throws Exception
    {
        generationTest(testMultipartMessage, testMultipartMessageContent);
    }

    private void generationTest(byte[] message, final byte[] messageContent)
        throws Exception
    {
        //
        // output
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        SMIMESignedWriter.Builder sigBldr = new SMIMESignedWriter.Builder();

        sigBldr.addCertificate(new JcaX509CertificateHolder(_signCert));
        
        sigBldr.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider(BC).build("SHA256withRSA", _signKP.getPrivate(), _signCert));

        SMIMESignedWriter sigWrt = sigBldr.build(bOut);

        OutputStream out = sigWrt.getContentStream();

        out.write(message);

        out.close();
        
        //
        // parse
        //
        final TestDoneFlag dataParsed = new TestDoneFlag();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(new ReadOnceInputStream(bOut.toByteArray()));

        p.parse(new SMimeParserListener()
        {
            public void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
                throws IOException
            {
                byte[] content = Streams.readAll(inputStream);

                assertTrue(org.bouncycastle.util.Arrays.areEqual(messageContent, content));
            }

            public void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
                throws IOException, CMSException
            {
                SignerInformation signerInfo = signers.get(new JcaSignerId(_signCert));

                assertNotNull(signerInfo);

                Collection certCollection = certificates.getMatches(signerInfo.getSID());

                Iterator certIt = certCollection.iterator();
                X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

                try
                {
                    assertEquals(true, signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder)));
                }
                catch (OperatorCreationException e)
                {
                    throw new CMSException(e.getMessage(), e);
                }
                catch (CertificateException e)
                {
                    throw new CMSException(e.getMessage(), e);
                }

                dataParsed.markDone();
            }
        });

        assertTrue(dataParsed.isDone());
    }
}
