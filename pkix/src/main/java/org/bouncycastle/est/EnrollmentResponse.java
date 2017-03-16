package org.bouncycastle.est;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;


/**
 * Holder class for a response containing the details making up a /simpleenroll response.
 */
public class EnrollmentResponse
{
    private final Store<X509CertificateHolder> store;
    private final long notBefore;
    private final ESTRequest requestToRetry;
    private final Source source;

    public EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTRequest requestToRetry, Source session)
    {
        this.store = store;
        this.notBefore = notBefore;
        this.requestToRetry = requestToRetry;
        this.source = session;
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
        return source.getSession();
    }

    public Source getSource()
    {
        return source;
    }

    public boolean isCompleted()
    {
        return requestToRetry == null;
    }
}
