package org.bouncycastle.est;


import javax.net.ssl.SSLSession;

import org.bouncycastle.est.http.ESTHttpClient;
import org.bouncycastle.est.http.TLSAuthorizer;

public interface ESTHttpClientProvider
{
    ESTHttpClient makeHttpClient(TLSAuthorizer<SSLSession> tlsAuthorizer)
        throws Exception;
}
