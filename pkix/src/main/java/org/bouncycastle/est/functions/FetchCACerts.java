package org.bouncycastle.est.functions;


import java.net.URL;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.http.ESTHttpClient;
import org.bouncycastle.est.http.ESTHttpException;
import org.bouncycastle.est.http.ESTHttpRequest;
import org.bouncycastle.est.http.ESTHttpResponse;
import org.bouncycastle.util.Store;


public class FetchCACerts
{

    private final ESTHttpClient client;

    public FetchCACerts(ESTHttpClient client)
    {
        this.client = client;
    }

    public Store<X509CertificateHolder> getCertificates(URL url, RFC7030BootstrapAuthorizer<SSLSession> bootstrapAuthorizer)
        throws Exception
    {
        Store<X509CertificateHolder> caCerts = null;
        ESTHttpResponse resp = null;
        try
        {
            resp = client.doRequest(new ESTHttpRequest("GET", url));

            if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
                caCerts = spkr.getCertificates();
                if (bootstrapAuthorizer != null)
                {
                    bootstrapAuthorizer.authorise(caCerts, ((SSLSocket)resp.getSocket()).getSession().getPeerCertificateChain());
                }
            }
            else
            {
                throw new ESTHttpException("Fetching cacerts: " + url.toString(), resp.getStatusCode(), resp.getStatusMessage(), resp.getInputStream(), (int)resp.getContentLength());
            }
        }
        catch (Exception ex)
        {
            if (ex instanceof ESTHttpException)
            {
                throw ex;
            }
            throw new ESTException(ex.getMessage(), ex);
        }
        finally
        {
            if (resp != null)
            {
                resp.close();
            }
        }
        return caCerts;
    }


}
