package org.bouncycastle.est;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;


/**
 * Holder class for a response containing the details making up a /simpleenroll response.
 */
public class EnrollmentResponse
{
    private final Store<X509CertificateHolder> store;
    private final PrivateKeyInfo privateKeyInfo;
    private final long notBefore;
    private final ESTRequest requestToRetry;
    private final Source source;

    public EnrollmentResponse(Store<X509CertificateHolder> store, PrivateKeyInfo privateKeyInfo, long notBefore, ESTRequest requestToRetry, Source session)
    {
        this.store = store;
        this.privateKeyInfo = privateKeyInfo;
        this.notBefore = notBefore;
        this.requestToRetry = requestToRetry;
        this.source = session;
    }

    public EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTRequest requestToRetry, Source session)
    {
        this(store, null, notBefore, requestToRetry, session);
    }

    public boolean canRetry()
    {
        return notBefore < System.currentTimeMillis();
    }

    public Store<X509CertificateHolder> getStore()
    {
        return store;
    }

    public PrivateKeyInfo getPrivateKeyInfo() {
        return privateKeyInfo;
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
