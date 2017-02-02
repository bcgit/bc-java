package org.bouncycastle.est;


import javax.net.ssl.SSLSession;

import org.bouncycastle.est.http.ESTHttpClient;
import org.bouncycastle.est.http.TLSAuthorizer;

public interface ESTHttpClientProvider<T>
{
    ESTHttpClient makeHttpClient(TLSAuthorizer<T> tlsAuthorizer)
        throws Exception;
}
