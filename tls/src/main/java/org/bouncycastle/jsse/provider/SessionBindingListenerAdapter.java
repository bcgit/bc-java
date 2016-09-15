package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;

class SessionBindingListenerAdapter implements SSLSessionBindingListener
{
    protected SSLSessionBindingListener listener;

    SessionBindingListenerAdapter(SSLSessionBindingListener listener)
    {
        this.listener = listener;
    }

    public void valueBound(SSLSessionBindingEvent event)
    {
        try
        {
            listener.valueBound(event);
        }
        catch (Exception x)
        {
            // TODO[tls-ops] Possible logging
        }
    }

    public void valueUnbound(SSLSessionBindingEvent event)
    {
        try
        {
            listener.valueUnbound(event);
        }
        catch (Exception x)
        {
            // TODO[tls-ops] Possible logging
        }
    }
}
