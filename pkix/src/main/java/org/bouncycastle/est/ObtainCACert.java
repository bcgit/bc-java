package org.bouncycastle.est;


import java.net.URL;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.functions.FetchCACerts;
import org.bouncycastle.est.http.DefaultESTClient;
import org.bouncycastle.est.http.DefaultESTClientSSLSocketProvider;
import org.bouncycastle.util.Store;


/**
 * Prototype implementation of RFC7030 Section 2.1 " Obtaining CA Certificates"
 * This is _not_ api.
 */
public class ObtainCACert
{
    public static void main(String[] args)
        throws Exception
    {
        new ObtainCACert(args);
    }

    private ObtainCACert(String[] args)
        throws Exception
    {


        String testURL = "https://testrfc7030.cisco.com:8443/.well-known/est/cacerts";

        //
        // Fetch using the default SSLSocket factory
        // No Hostname verification or boot strap authorizer.
        //
        FetchCACerts fetchCACerts = new FetchCACerts(
            new DefaultESTClient(
                DefaultESTClientSSLSocketProvider.getUsingDefaultSSLSocketFactory(null)));

        Store<X509CertificateHolder> store = fetchCACerts.getCertificates(new URL(testURL), null);

        Collection<X509CertificateHolder> all = store.getMatches(null);
        for (X509CertificateHolder h : all)
        {
            System.out.println(h.getSubject());
            System.out.println(h.getIssuer());
        }

    }


}
