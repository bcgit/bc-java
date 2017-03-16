package org.bouncycastle.jsse.provider;

class ProvSSLParameters
{
    static final boolean hasSslParameters;

    static
    {
        Class clazz = null;
        try
        {
            clazz = ProvSSLServerSocket.class.getClassLoader().loadClass("javax.net.ssl.SSLParameters");
        }
        catch (Exception e)
        {
            clazz = null;
        }

        hasSslParameters = (clazz != null);
    }

    private String[] cipherSuites;
    private String[] protocols;
    private boolean needClientAuth;
    private boolean wantClientAuth;

    public void setCipherSuites(String[] cipherSuites)
    {
        this.cipherSuites = cipherSuites;
    }

    public void setProtocols(String[] protocols)
    {
        this.protocols = protocols;
    }

    public void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth)
    {
        this.wantClientAuth = wantClientAuth;
    }

    public String[] getCipherSuites()
    {
        return cipherSuites.clone();
    }

    public String[] getProtocols()
    {
        return protocols.clone();
    }

    public boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

    public boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    static ProvSSLParameters extractDefaultParameters(ProvSSLContextSpi context)
    {
        if (hasSslParameters)
        {
            return SSLParametersUtil.toProvSSLParameters(context.engineGetDefaultSSLParameters());
        }
        else
        {
            ProvSSLParameters params = new ProvSSLParameters();

            String[] cipherSuites = context.getDefaultCipherSuites();
            if (cipherSuites != null)
            {
                params.setCipherSuites(cipherSuites);
            }
            String[] protocols = context.getDefaultProtocols();
            if (protocols != null)
            {
                params.setProtocols(protocols);
            }

            params.setNeedClientAuth(false);
            params.setWantClientAuth(false);

            return params;
        }
    }
}
