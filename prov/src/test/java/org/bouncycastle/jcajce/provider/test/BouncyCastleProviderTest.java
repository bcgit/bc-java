package org.bouncycastle.jcajce.provider.test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleProviderTest
    extends TestCase
{

    private BouncyCastleProvider provider;

    protected void setUp()
    {
        provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    protected void tearDown()
    {
        Security.removeProvider(provider.getName());
    }

    public void testRegisteredClasses()
    {
        Set<Object> keys = new TreeSet<Object>(provider.keySet());
        List<String> errors = new ArrayList<String>();

        for (Object rawKey : keys)
        {
            try
            {
                assertTrue(rawKey instanceof String);
                String key = (String)rawKey;

                if (key.startsWith("Alg.Alias."))
                {
                    // Skip aliases
                }
                else
                {
                    Object rawValue = provider.get(key);
                    assertTrue(rawValue instanceof String);
                    String value = (String)rawValue;

                    if (value.startsWith("org.bouncycastle."))
                    {
                        if (key.startsWith("CertStore."))
                        {
                            // CertStore classes have no appropriate constructors
                            resolveClass(key, value);
                        }
                        else
                        {
                            newInstance(key, resolveClass(key, value));
                        }
                    }
                }
            }
            catch (AssertionError e)
            {
                errors.add(e.getMessage());
            }
        }

        if (!errors.isEmpty())
        {
            throw new AssertionError("Failed with the following errors:\n" + String.join("\n", errors));
        }
    }

    /*
        public void testAliases() {
            Set<Object> keys = new TreeSet<>(provider.keySet());
            List<String> errors = new ArrayList<>();
    
            for (Object rawKey : keys) {
                try {
                    assertTrue(rawKey instanceof String);
                    String key = (String) rawKey;
    
                    if (key.startsWith("Alg.Alias.")) {
                        Object rawValue = provider.get(key);
                        assertTrue(rawValue instanceof String);
                        String value = (String) rawValue;
    
                        String internal = key.substring("Alg.Alias.".length()).split("\\.")[0];
                        if (!value.startsWith("org.bouncycastle.")) {
                            String chainedKey = internal + "." + value;
    
                            Object rawChainedValue = provider.get(chainedKey);
                            assertNotNull(String.format("Key [%s] links to missed key [%s]", key, chainedKey), rawChainedValue);
                            assertTrue(rawChainedValue instanceof String);
                        }
                    }
                } catch (AssertionError e) {
                    errors.add(e.getMessage());
                }
            }
    
            if (!errors.isEmpty()) {
                throw new AssertionError("Failed with the following errors:\n" + String.join("\n", errors));
            }
        }
    */
    private static <T> Class<T> resolveClass(String key, String className)
    {
        try
        {
            return (Class<T>)Class.forName(className);
        }
        catch (ClassNotFoundException e)
        {
            throw new AssertionError(String.format("Key [%s] contains wrong class name: %s", key, className));
        }
    }

    private static <T> T newInstance(String key, Class<T> clazz, Object... params)
    {
        try
        {
            if (params.length == 0)
            {
                return clazz.getConstructor().newInstance();
            }
            else
            {
                throw new IllegalStateException();
            }
        }
        catch (IllegalAccessException e)
        {
            throw new AssertionError(String.format("Key [%s] contains class which failed on instance creation: %s %s", key, clazz.getName(), e.getMessage()));
        }
        catch (NoSuchMethodException e)
        {
            throw new AssertionError(String.format("Key [%s] contains class which failed on instance creation: %s %s", key, clazz.getName(), e.getMessage()));
        }
        catch (Throwable e)
        {
            Throwable cause = e.getCause();
            if (cause == null)
            {
                cause = e;
            }
            StringWriter out = new StringWriter();
            e.printStackTrace(new PrintWriter(out));
            throw new AssertionError(String.format("Key [%s] contains class which failed on instance creation: %s %s\n%s", key, clazz.getName(), cause.getMessage(), out.toString()));
        }
    }
}