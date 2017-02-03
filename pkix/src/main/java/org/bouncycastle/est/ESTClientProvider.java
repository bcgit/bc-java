package org.bouncycastle.est;


public interface ESTClientProvider<T>
{
    ESTClient makeHttpClient()
        throws Exception;

    boolean isTrusted();
}
