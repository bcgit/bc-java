package org.bouncycastle.est;


import org.bouncycastle.est.http.ESTHttpClient;

public interface ESTHttpClientProvider<T>
{
    ESTHttpClient makeHttpClient()
        throws Exception;

    boolean isTrusted();
}
