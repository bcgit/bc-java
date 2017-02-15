package org.bouncycastle.est;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;


public class EnrollmentResponse
{
    private final Store<X509CertificateHolder> store;
    private final long notBefore;
    private final ESTRequest requestToRetry;
    private final Source session;

    public EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTRequest requestToRetry, Source session)
    {
        this.store = store;
        this.notBefore = notBefore;
        this.requestToRetry = requestToRetry;
        this.session = session;
    }

    public boolean canRetry()
    {
        return notBefore < System.currentTimeMillis();
    }

    public Store<X509CertificateHolder> getStore()
    {
        return store;
    }

    public long getNotBefore()
    {
        return notBefore;
    }

    public ESTRequest getRequestToRetry()
    {
        return requestToRetry;
    }

    public Object getSession()
    {
        return session.getSession();
    }

    public boolean isCompleted()
    {
        return requestToRetry == null;
    }
}
