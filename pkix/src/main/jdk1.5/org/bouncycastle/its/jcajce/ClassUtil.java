package org.bouncycastle.its.jcajce;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.Integers;

class ClassUtil
{
    private static final Class gcmSpecClass = loadClass(ClassUtil.class, "javax.crypto.spec.GCMParameterSpec");

    public static AlgorithmParameterSpec getGCMSpec(final byte[] nonce, final int tagSize)
    {
        if (gcmSpecClass != null)
        {
              try
              {
                  return (AlgorithmParameterSpec)AccessController.doPrivileged(new PrivilegedAction()
                  {
                      @Override
                      public Object run()
                      {
                          try
                          {
                              Constructor cons = gcmSpecClass.getConstructor(new Class[] { Integer.TYPE, byte[].class });

                              return cons.newInstance(Integers.valueOf(tagSize), nonce);
                          }
                          catch (NoSuchMethodException e)
                          {
                              throw new IllegalStateException("no matching constructor: " + e.getMessage());
                          }
                          catch (Exception e)
                          {
                              throw new IllegalStateException("constructor failed" + e.getMessage());
                          }
                      }
                  });
              }
              catch (IllegalStateException e)
              {
		  // ignore
              }
        }
        return new AEADParameterSpec(nonce, tagSize);
    }

    static Class loadClass(Class sourceClass, final String className)
        {
            try
            {
                ClassLoader loader = sourceClass.getClassLoader();

                if (loader != null)
                {
                    return loader.loadClass(className);
                }
                else
                {
                    return (Class)AccessController.doPrivileged(new PrivilegedAction()
                    {
                        public Object run()
                        {
                            try
                            {
                                return Class.forName(className);
                            }
                            catch (Exception e)
                            {
                                // ignore - maybe log?
                            }

                            return null;
                        }
                    });
                }
            }
            catch (ClassNotFoundException e)
            {
                // ignore - maybe log?
            }

            return null;
        }
}
