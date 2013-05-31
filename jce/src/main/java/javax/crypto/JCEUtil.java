package javax.crypto;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Locale;

class JCEUtil
{
    static class Implementation
    {
        Object      engine;
        Provider    provider;

        Implementation(
            Object      engine,
            Provider    provider)
        {
            this.engine = engine;
            this.provider = provider;
        }

        Object getEngine()
        {
            return engine;
        }

        Provider getProvider()
        {
            return provider;
        }
    }

    /**
     * see if we can find an algorithm (or its alias and what it represents) in
     * the property table for the given provider.
     *
     * @return null if no algorithm found, an Implementation if it is.
     */
    static private Implementation findImplementation(
        String      baseName,
        String      algorithm,
        Provider    prov)
    {
        String      alias;

        while ((alias = prov.getProperty("Alg.Alias." + baseName + "." + algorithm)) != null)
        {
            algorithm = alias;
        }

        String      className = prov.getProperty(baseName + "." + algorithm);

        if (className != null)
        {
            try
            {
                Class       cls;
                ClassLoader clsLoader = prov.getClass().getClassLoader();

                if (clsLoader != null)
                {
                    cls = clsLoader.loadClass(className);
                }
                else
                {
                    cls = Class.forName(className);
                }

                return new Implementation(cls.newInstance(), prov);
            }
            catch (ClassNotFoundException e)
            {
                throw new IllegalStateException(
                    "algorithm " + algorithm + " in provider " + prov.getName() + " but no class \"" + className + "\" found!");
            }
            catch (Exception e)
            {
                throw new IllegalStateException(
                    "algorithm " + algorithm + " in provider " + prov.getName() + " but class \"" + className + "\" inaccessible!");
            }
        }

        return null;
    }

    /**
     * return an implementation for a given algorithm/provider.
     * If the provider is null, we grab the first avalaible who has the required algorithm.
     *
     * @return null if no algorithm found, an Implementation if it is.
     * @exception NoSuchProviderException if a provider is specified and not found.
     */
    static Implementation getImplementation(
        String      baseName,
        String      algorithm,
        String      provider)
        throws NoSuchProviderException
    {
        if (provider == null)
        {
            Provider[] prov = Security.getProviders();

            //
            // search every provider looking for the algorithm we want.
            //
            for (int i = 0; i != prov.length; i++)
            {
                //
                // try case insensitive
                //
                Implementation imp = findImplementation(baseName, algorithm.toUpperCase(Locale.ENGLISH), prov[i]);
                if (imp != null)
                {
                    return imp;
                }

                imp = findImplementation(baseName, algorithm, prov[i]);
                if (imp != null)
                {
                    return imp;
                }
            }
        }
        else
        {
            Provider prov = Security.getProvider(provider);

            if (prov == null)
            {
                throw new NoSuchProviderException("Provider " + provider + " not found");
            }

            //
            // try case insensitive
            //
            Implementation imp = findImplementation(baseName, algorithm.toUpperCase(Locale.ENGLISH), prov);
            if (imp != null)
            {
                return imp;
            }

            return findImplementation(baseName, algorithm, prov);
        }

        return null;
    }

    /**
     * return an implementation for a given algorithm/provider.
     * If the provider is null, we grab the first avalaible who has the required algorithm.
     *
     * @return null if no algorithm found, an Implementation if it is.
     * @exception NoSuchProviderException if a provider is specified and not found.
     */
    static Implementation getImplementation(
        String      baseName,
        String      algorithm,
        Provider    provider)
    {
        if (provider == null)
        {
            Provider[] prov = Security.getProviders();

            //
            // search every provider looking for the algorithm we want.
            //
            for (int i = 0; i != prov.length; i++)
            {
                //
                // try case insensitive
                //
                Implementation imp = findImplementation(baseName, algorithm.toUpperCase(Locale.ENGLISH), prov[i]);
                if (imp != null)
                {
                    return imp;
                }

                imp = findImplementation(baseName, algorithm, prov[i]);
                if (imp != null)
                {
                    return imp;
                }
            }
        }
        else
        {
            //
            // try case insensitive
            //
            Implementation imp = findImplementation(baseName, algorithm.toUpperCase(Locale.ENGLISH), provider);
            if (imp != null)
            {
                return imp;
            }

            return findImplementation(baseName, algorithm, provider);
        }

        return null;
    }
}
