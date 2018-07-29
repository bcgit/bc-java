package org.bouncycastle.mime.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import junit.framework.TestCase;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.OriginatorInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeParser;
import org.bouncycastle.mime.MimeParserProvider;
import org.bouncycastle.mime.smime.SMimeParserListener;
import org.bouncycastle.mime.smime.SMimeParserProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Base64;

public class TestSMIMEEnvelope
    extends TestCase
{
    private static final byte[] testMessage = Base64.decode(
        "TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L21peGVkOyANCglib3VuZGFye" +
        "T0iLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyIg0KQ29udGVudC1MYW5ndWFnZTogZW" +
        "4NCkNvbnRlbnQtRGVzY3JpcHRpb246IEEgbWFpbCBmb2xsb3dpbmcgdGhlIERJUkVDVCBwcm9qZWN0IHN" +
        "wZWNpZmljYXRpb25zDQoNCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzUwMTMyDQpDb250" +
        "ZW50LVR5cGU6IHRleHQvcGxhaW47IG5hbWU9bnVsbDsgY2hhcnNldD11cy1hc2NpaQ0KQ29udGVudC1Uc" +
        "mFuc2Zlci1FbmNvZGluZzogN2JpdA0KQ29udGVudC1EaXNwb3NpdGlvbjogaW5saW5lOyBmaWxlbmFtZT" +
        "1udWxsDQoNCkNpYW8gZnJvbSB2aWVubmENCi0tLS0tLT1fUGFydF8wXzI2MDM5NjM4Ni4xMzUyOTA0NzU" +
        "wMTMyLS0NCg==");

    public void testSMIMEEnvelope()
        throws Exception
    {

        InputStream inputStream = this.getClass().getResourceAsStream("test256.message");

        final ArrayList<Object> results = new ArrayList<Object>();

        MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

        MimeParser p = provider.createParser(inputStream);

        Security.addProvider(new BouncyCastleProvider());

        p.parse(new SMimeParserListener()
        {
            public void envelopedData(Headers headers, OriginatorInformation originator, RecipientInformationStore recipients)
                throws IOException, CMSException
            {
                RecipientInformation recipInfo = recipients.get(new JceKeyTransRecipientId(loadCert("cert.pem")));

                assertNotNull(recipInfo);
                
                    byte[] content = recipInfo.getContent(new JceKeyTransEnvelopedRecipient(loadKey("key.pem")));
                    assertTrue(org.bouncycastle.util.Arrays.areEqual(testMessage, content));
            }
        });
    }

    private X509Certificate loadCert(String name)
        throws IOException
    {
        try
        {
            return (X509Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(getClass().getResourceAsStream(name));
        }
        catch (Exception e)
        {
            throw new IOException(e.getMessage());
        }
    }

    private PrivateKey loadKey(String name)
        throws IOException
    {
        return new JcaPEMKeyConverter().setProvider("BC").getKeyPair((PEMKeyPair)(new PEMParser(new InputStreamReader(getClass().getResourceAsStream(name)))).readObject()).getPrivate();
    }
}
