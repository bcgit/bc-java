package org.bouncycastle.est.functions;


import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.http.ESTClientRequestInputSource;
import org.bouncycastle.est.http.ESTHttpClient;
import org.bouncycastle.est.http.ESTHttpException;
import org.bouncycastle.est.http.ESTHttpRequest;
import org.bouncycastle.est.http.ESTHttpResponse;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

public class SimpleEnroll
{

    private final ESTHttpClient client;

    public SimpleEnroll(ESTHttpClient client)
    {
        this.client = client;
    }

    public Store<X509CertificateHolder> simpleEnrolBasicAuth(URL url, String user, String password, PKCS10CertificationRequest request)
        throws Exception
    {
        Store<X509CertificateHolder> enrolled = null;
        ESTHttpResponse resp = null;

        try
        {
            final byte[] data = split(request.getEncoded()).getBytes();
            ESTHttpRequest req = new ESTHttpRequest("POST", url, new ESTClientRequestInputSource()
            {
                public void ready(OutputStream os)
                    throws IOException
                {
                    os.write(data);
                    os.flush();
                }
            }).withBasicAuth(null, user, password);

            req.addHeader("Content-Type", "application/pkcs10");
            req.addHeader("content-length", "" + data.length);

            resp = client.doRequest(req);

            if (resp.getStatusCode() == 200)
            {
                ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
                SimplePKIResponse respSpkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
                enrolled = respSpkr.getCertificates();
            }
            else
            {
                throw new ESTHttpException("Simple Enrol: " + url.toString(), resp.getStatusCode(), resp.getStatusMessage(), resp.getInputStream(), (int)resp.getContentLength());
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
        return enrolled;
    }

    private String split(byte[] data)
    {
        int i = 0;
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.print("-----BEGIN CERTIFICATE REQUEST-----\n");
        do
        {
            if (i + 48 < data.length)
            {
                pw.print(Base64.toBase64String(data, i, 48));
                i += 48;
            }
            else
            {
                pw.print(Base64.toBase64String(data, i, data.length - i));
                i = data.length;
            }
            pw.print('\n');
        }
        while (i < data.length);
        pw.print("-----END CERTIFICATE REQUEST-----\n");
        pw.flush();
        return sw.toString();
    }
}
