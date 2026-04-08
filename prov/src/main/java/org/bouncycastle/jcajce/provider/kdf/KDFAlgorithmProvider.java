package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

abstract class KDFAlgorithmProvider
    extends AlgorithmProvider
{
    void addKDFAlgorithm(ConfigurableProvider provider, String algorithm, String className)
    {
        addKDFAlgorithm(provider, algorithm, className, null);
    }

    void addKDFAlgorithm(ConfigurableProvider provider, String algorithm, String className, ASN1ObjectIdentifier oid)
    {
        provider.addAlgorithm("KDF." + algorithm, className);
        if (oid != null)
        {
            registerKDFAliasOid(provider, oid, algorithm);
        }
    }

    void registerKDFAlias(ConfigurableProvider provider, String alias, String algorithm)
    {
        provider.addAlgorithm("Alg.Alias.KDF." + alias, algorithm);
    }

    void registerKDFAliasOid(ConfigurableProvider provider, ASN1ObjectIdentifier oid, String algorithm)
    {
        provider.addAlgorithm("Alg.Alias.KDF." + oid, algorithm);
        provider.addAlgorithm("Alg.Alias.KDF.OID." + oid, algorithm);
    }
}
