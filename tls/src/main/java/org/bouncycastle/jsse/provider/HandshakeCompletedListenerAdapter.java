package org.bouncycastle.jsse.provider;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;

class HandshakeCompletedListenerAdapter
    implements HandshakeCompletedListener
{
    protected final HandshakeCompletedListener listener;

    HandshakeCompletedListenerAdapter(HandshakeCompletedListener listener)
    {
        this.listener = listener;
    }

    public void handshakeCompleted(final HandshakeCompletedEvent event)
    {
        CallbackUtil.safeCallback(new Runnable(){
            public void run()
            {
                listener.handshakeCompleted(event);
            }
        });
    }

    @Override
    public boolean equals(Object obj)
    {
        return (obj instanceof HandshakeCompletedListenerAdapter)
            && ((HandshakeCompletedListenerAdapter)obj).listener == listener;
    }

    @Override
    public int hashCode()
    {
        return System.identityHashCode(listener);
    }
}
