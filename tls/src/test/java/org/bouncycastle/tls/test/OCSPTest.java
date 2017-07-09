package org.bouncycastle.tls.test;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate;

public class OCSPTest
    extends TestCase
{
    interface OCSPResponder
    {
        OCSPResponse[] getResponses(Certificate certs)
            throws IOException;
    }

    private class TestOCSPResponderImpl
        implements OCSPResponder
    {
        private final TestOCSPCertServer server;
        private final DigestCalculator digCalc;
        private final X509Certificate caCert;

        public TestOCSPResponderImpl(TestOCSPCertServer server)
            throws OperatorCreationException
        {
            this.server = server;
            this.caCert = server.getCACert();
            this.digCalc = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        }

        public OCSPResponse[] getResponses(Certificate certs)
            throws IOException
        {
            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            TlsCertificate[] certList = certs.getCertificateList();

            for (int i = 0; i != certList.length; i++)
            {
                try
                {
                    reqBuilder.addRequest(new CertificateID(digCalc, new X509CertificateHolder(caCert.getEncoded()), certList[i].getSerialNumber()));
                }
                catch (OCSPException e)
                {
                    throw new IOException("OCSP issue: " + e.getMessage());
                }
                catch (CertificateEncodingException e)
                {
                    throw new IOException("CA encoding issue: " + e.getMessage());
                }
            }

            try
            {
                // in this case a single response contains all the status messages
                return new OCSPResponse[] { server.respond(reqBuilder.build()).toASN1Structure() };
            }
            catch (Exception e)
            {
                throw new IOException("OCSP response issue: " + e.getMessage());
            }
        }
    }

    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public void testOCSPResponder()
        throws Exception
    {
        JcaJceHelper helper = new DefaultJcaJceHelper();
        DigestCalculator digCalc = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        TestOCSPCertServer server = new TestOCSPCertServer();
        X509Certificate caCert = server.getCACert();

        X509CertificateHolder cert1 = server.issueClientCert("CN=Okay", false).getCertificate();

        X509CertificateHolder cert2 = server.issueClientCert("CN=Revoked", true).getCertificate();

        OCSPResponder responder = new TestOCSPResponderImpl(server);

        Certificate certs = new Certificate(new TlsCertificate[] { new JcaTlsCertificate(cert1.getEncoded(), helper), new JcaTlsCertificate(cert2.getEncoded(), helper) });

        OCSPResponse[] responses = responder.getResponses(certs);

        assertEquals(1, responses.length);

        OCSPResponse response = responses[0];

        assertEquals(OCSPResponseStatus.SUCCESSFUL, response.getResponseStatus().getValue().intValue());
        assertEquals(OCSPObjectIdentifiers.id_pkix_ocsp_basic, response.getResponseBytes().getResponseType());
        
        BasicOCSPResp basicResp = new BasicOCSPResp(BasicOCSPResponse.getInstance(response.getResponseBytes().getResponse().getOctets()));

        SingleResp[] resps = basicResp.getResponses();

        assertEquals(2, resps.length);

        assertEquals(resps[0].getCertID(), new JcaCertificateID(digCalc, caCert, cert1.getSerialNumber()));
        assertNull(resps[0].getCertStatus());        // OKAY
        assertEquals(resps[1].getCertID(), new JcaCertificateID(digCalc, caCert, cert2.getSerialNumber()));
        assertNotNull(resps[1].getCertStatus());     // revoked
    }
}
