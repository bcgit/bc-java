package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.net.ssl.SSLParameters;

class SSLParametersUtil
{
    private static final Method getAlgorithmConstraints;
    private static final Method setAlgorithmConstraints;
    private static final Method getEndpointIdentificationAlgorithm;
    private static final Method setEndpointIdentificationAlgorithm;
    private static final Method getUseCipherSuitesOrder;
    private static final Method setUseCipherSuitesOrder;

    static
    {
        final Class paramDef = AccessController.doPrivileged(new PrivilegedAction<Class>()
          {
              public Class run()
              {
                  try
                  {
                      return BouncyCastleJsseProvider.class.getClassLoader().loadClass("javax.net.ssl.SSLParameters");
                  }
                  catch (Exception e)
                  {
                      return null;
                  }
              }
          });

        if (paramDef != null)
        {
            getAlgorithmConstraints = AccessController.doPrivileged(new PrivilegedAction<Method>()
               {
                   public Method run()
                   {
                       try
                       {
                           return paramDef.getMethod("getAlgorithmConstraints");
                       }
                       catch (Exception e)
                       {
                           return null;
                       }
                   }
               });
            setAlgorithmConstraints = AccessController.doPrivileged(new PrivilegedAction<Method>()
               {
                   public Method run()
                   {
                       try
                       {
                           return paramDef.getMethod("setAlgorithmConstraints");
                       }
                       catch (Exception e)
                       {
                           return null;
                       }
                   }
               });
            getEndpointIdentificationAlgorithm = AccessController.doPrivileged(new PrivilegedAction<Method>()
               {
                   public Method run()
                   {
                       try
                       {
                           return paramDef.getMethod("getEndpointIdentificationAlgorithm");
                       }
                       catch (Exception e)
                       {
                           return null;
                       }
                   }
               });
            setEndpointIdentificationAlgorithm = AccessController.doPrivileged(new PrivilegedAction<Method>()
               {
                   public Method run()
                   {
                       try
                       {
                           return paramDef.getMethod("setEndpointIdentificationAlgorithm");
                       }
                       catch (Exception e)
                       {
                           return null;
                       }
                   }
               });
            getUseCipherSuitesOrder = AccessController.doPrivileged(new PrivilegedAction<Method>()
               {
                   public Method run()
                   {
                       try
                       {
                           return paramDef.getMethod("getUseCipherSuitesOrder");
                       }
                       catch (Exception e)
                       {
                           return null;
                       }
                   }
               });
            setUseCipherSuitesOrder = AccessController.doPrivileged(new PrivilegedAction<Method>()
               {
                   public Method run()
                   {
                       try
                       {
                           return paramDef.getMethod("setUseCipherSuitesOrder");
                       }
                       catch (Exception e)
                       {
                           return null;
                       }
                   }
               });
        }
        else
        {
            getAlgorithmConstraints = null;
            setAlgorithmConstraints = null;
            getEndpointIdentificationAlgorithm = null;
            setEndpointIdentificationAlgorithm = null;
            getUseCipherSuitesOrder = null;
            setUseCipherSuitesOrder = null;
        }
    }

    static SSLParameters toSSLParameters(final ProvSSLParameters provSslParameters)
    {
        final SSLParameters r = new SSLParameters();
        r.setCipherSuites(provSslParameters.getCipherSuites());
        r.setProtocols(provSslParameters.getProtocols());
        // From JDK 1.7
        if (setAlgorithmConstraints != null)
        {
              AccessController.doPrivileged(new PrivilegedAction<Object>()
              {
                  public Object run()
                  {
                      try
                      {
                          setAlgorithmConstraints.invoke(r, provSslParameters.getAlgorithmConstraints());
                      }
                      catch (Exception e)
                      {
                          // TODO: log?
                      }
                      return null;
                  }
              });
        }
        if (setEndpointIdentificationAlgorithm != null)
        {
              AccessController.doPrivileged(new PrivilegedAction<Object>()
              {
                  public Object run()
                  {
                      try
                      {
                          setEndpointIdentificationAlgorithm.invoke(r, provSslParameters.getEndpointIdentificationAlgorithm());
                      }
                      catch (Exception e)
                      {
                          // TODO: log?
                      }
                      return null;
                  }
              });
        }
        // TODO[jsse] From JDK 1.8
//        r.setServerNames(p.getServerNames());
//        r.setSNIMatchers(p.getSNIMatchers());
        if (setUseCipherSuitesOrder != null)
        {
              AccessController.doPrivileged(new PrivilegedAction<Object>()
              {
                  public Object run()
                  {
                      try
                      {
                          setUseCipherSuitesOrder.invoke(r, provSslParameters.getUseCipherSuitesOrder());
                      }
                      catch (Exception e)
                      {
                          // TODO: log?
                      }
                      return null;
                  }
              });
        }
        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (provSslParameters.getNeedClientAuth())
        {
            r.setNeedClientAuth(true);
        }
        else if (provSslParameters.getWantClientAuth())
        {
            r.setWantClientAuth(true);
        }
        else
        {
            r.setWantClientAuth(false);
        }
        return r;
    }

    static ProvSSLParameters toProvSSLParameters(final SSLParameters sslParameters)
    {
        final ProvSSLParameters r = new ProvSSLParameters();
        r.setCipherSuites(sslParameters.getCipherSuites());
        r.setProtocols(sslParameters.getProtocols());
        // From JDK 1.7
        if (getAlgorithmConstraints != null)
        {
              r.setAlgorithmConstraints(AccessController.doPrivileged(new PrivilegedAction<Object>()
              {
                  public Object run()
                  {
                      try
                      {
                          return getAlgorithmConstraints.invoke(sslParameters);
                      }
                      catch (Exception e)
                      {
                          // TODO: log?
                          return null;
                      }
                  }
              }));
        }
        if (getEndpointIdentificationAlgorithm != null)
        {
              r.setEndpointIdentificationAlgorithm(AccessController.doPrivileged(new PrivilegedAction<String>()
              {
                  public String run()
                  {
                      try
                      {
                          return (String)getEndpointIdentificationAlgorithm.invoke(sslParameters);
                      }
                      catch (Exception e)
                      {
                          // TODO: log?
                          return null;
                      }
                  }
              }));
        }
        // TODO[jsse] From JDK 1.8
//        r.setServerNames(p.getServerNames());
//        r.setSNIMatchers(p.getSNIMatchers());
        if (getUseCipherSuitesOrder != null)
        {
              r.setUseCipherSuitesOrder(AccessController.doPrivileged(new PrivilegedAction<Boolean>()
              {
                  public Boolean run()
                  {
                      try
                      {
                          return (Boolean)getUseCipherSuitesOrder.invoke(sslParameters);
                      }
                      catch (Exception e)
                      {
                          // TODO: log?
                          return null;
                      }
                  }
              }));
        }

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (sslParameters.getNeedClientAuth())
        {
            r.setNeedClientAuth(true);
        }
        else if (sslParameters.getWantClientAuth())
        {
            r.setWantClientAuth(true);
        }
        else
        {
            r.setWantClientAuth(false);
        }
        return r;
    }
}
