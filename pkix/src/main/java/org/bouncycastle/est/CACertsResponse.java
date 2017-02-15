package org.bouncycastle.est;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;

public class CACertsResponse
{
    private final Store<X509CertificateHolder> store;
    private final ESTRequest requestToRetry;
    private final Source session;
    private final boolean trusted;

    public CACertsResponse(Store<X509CertificateHolder> store, ESTRequest requestToRetry, Source session, boolean trusted)
    {
        this.store = store;
        this.requestToRetry = requestToRetry;
        this.session = session;
        this.trusted = trusted;
    }

    public Store<X509CertificateHolder> getStore()
    {
        return store;
    }

    public ESTRequest getRequestToRetry()
    {
        return requestToRetry;
    }

    public Object getSession()
    {
        return session.getSession();
    }

    public boolean isTrusted()
    {
        return trusted;
    }
}
