package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;

class SessionBindingListenerAdapter
    implements SSLSessionBindingListener
{
    protected final SSLSessionBindingListener listener;

    SessionBindingListenerAdapter(SSLSessionBindingListener listener)
    {
        this.listener = listener;
    }

    public void valueBound(final SSLSessionBindingEvent event)
    {
        CallbackUtil.safeCallback(new Runnable(){
            public void run()
            {
                listener.valueBound(event);
            }
        });
    }

    public void valueUnbound(final SSLSessionBindingEvent event)
    {
        CallbackUtil.safeCallback(new Runnable(){
            public void run()
            {
                listener.valueUnbound(event);
            }
        });
    }
}
