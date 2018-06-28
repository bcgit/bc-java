package org.bouncycastle.jce.provider;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import java.security.spec.DSAParameterSpec;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.spec.ECParameterSpec;

class BouncyCastleProviderConfiguration
    implements ProviderConfiguration
{
    private Map ecThreadSpec = new HashMap();
    private Map dhThreadSpec = new HashMap();

    private volatile ECParameterSpec ecImplicitCaParams;
    private volatile Object dhDefaultParams;
    private volatile Set acceptableNamedCurves = new HashSet();
    private volatile Map additionalECParameters = new HashMap();

    void setParameter(String parameterName, Object parameter)
    {
        SecurityManager securityManager = System.getSecurityManager();

        if (parameterName.equals(ConfigurableProvider.THREAD_LOCAL_EC_IMPLICITLY_CA))
        {
            ECParameterSpec curveSpec;

            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                curveSpec = (ECParameterSpec)parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid ECParameterSpec");
            }

            if (curveSpec == null)
            {
                ecThreadSpec.remove(Thread.currentThread());
            }
            else
            {
                ecThreadSpec.put(Thread.currentThread(), curveSpec);
            }
        }
        else if (parameterName.equals(ConfigurableProvider.EC_IMPLICITLY_CA))
        {
            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                ecImplicitCaParams = (ECParameterSpec)parameter;
            }
            else  // assume java.security.spec
            {
                throw new IllegalArgumentException("not a valid ECParameterSpec");
            }
        }
        else if (parameterName.equals(ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS))
        {
            Object dhSpec;

            if (parameter instanceof DHParameterSpec || parameter instanceof DHParameterSpec[] || parameter == null)
            {
                dhSpec = parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec");
            }

            if (dhSpec == null)
            {
                dhThreadSpec.remove(Thread.currentThread());
            }
            else
            {
                dhThreadSpec.put(Thread.currentThread(), dhSpec);
            }
        }
        else if (parameterName.equals(ConfigurableProvider.DH_DEFAULT_PARAMS))
        {
            if (parameter instanceof DHParameterSpec || parameter instanceof DHParameterSpec[] || parameter == null)
            {
                dhDefaultParams = parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec or DHParameterSpec[]");
            }
        }
        else if (parameterName.equals(ConfigurableProvider.ACCEPTABLE_EC_CURVES))
        {
            this.acceptableNamedCurves = (Set)parameter;
        }
        else if (parameterName.equals(ConfigurableProvider.ADDITIONAL_EC_PARAMETERS))
        {
            this.additionalECParameters = (Map)parameter;
        }
    }

    public ECParameterSpec getEcImplicitlyCa()
    {
        ECParameterSpec spec = (ECParameterSpec)ecThreadSpec.get(Thread.currentThread());

        if (spec != null)
        {
            return spec;
        }

        return ecImplicitCaParams;
    }

    public DHParameterSpec getDHDefaultParameters(int keySize)
    {
        Object params = dhThreadSpec.get(Thread.currentThread());
        if (params == null)
        {
            params = dhDefaultParams;
        }

        if (params instanceof DHParameterSpec)
        {
            DHParameterSpec spec = (DHParameterSpec)params;

            if (spec.getP().bitLength() == keySize)
            {
                return spec;
            }
        }
        else if (params instanceof DHParameterSpec[])
        {
            DHParameterSpec[] specs = (DHParameterSpec[])params;

            for (int i = 0; i != specs.length; i++)
            {
                if (specs[i].getP().bitLength() == keySize)
                {
                    return specs[i];
                }
            }
        }

        DHParameters dhParams = (DHParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, keySize);
        if (dhParams != null)
        {
            return new DHDomainParameterSpec(dhParams);
        }

        return null;
    }

    public DSAParameterSpec getDSADefaultParameters(int keySize)
    {
        DSAParameters dsaParams = (DSAParameters)CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, keySize);
        if (dsaParams != null)
        {
            return new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
        }

        return null;
    }

    public Set getAcceptableNamedCurves()
    {
        return Collections.unmodifiableSet(acceptableNamedCurves);
    }

    public Map getAdditionalECParameters()
    {
        return Collections.unmodifiableMap(additionalECParameters);
    }
}
