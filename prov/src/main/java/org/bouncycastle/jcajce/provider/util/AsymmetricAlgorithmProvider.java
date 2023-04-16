package org.bouncycastle.jcajce.provider.util;

import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

public abstract class AsymmetricAlgorithmProvider
    extends AlgorithmProvider
{
    protected void addSignatureAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid)
    {
        provider.addAlgorithm("Signature." + algorithm, className);
        provider.addAlgorithm("Alg.Alias.Signature." + oid, algorithm);
        provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, algorithm);
    }

    protected void addSignatureAlias(
        ConfigurableProvider provider,
        String algorithm,
        ASN1ObjectIdentifier oid)
    {
        provider.addAlgorithm("Alg.Alias.Signature." + oid, algorithm);
        provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, algorithm);
    }

    protected void addSignatureAlgorithm(
        ConfigurableProvider provider,
        String digest,
        String algorithm,
        String className)
    {
        addSignatureAlgorithm(provider, digest, algorithm, className, null);
    }

    protected void addSignatureAlgorithm(
        ConfigurableProvider provider,
        String digest,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid)
    {
        String mainName = digest + "WITH" + algorithm;
        String jdk11Variation1 = digest + "with" + algorithm;
        String jdk11Variation2 = digest + "With" + algorithm;
        String alias = digest + "/" + algorithm;

        provider.addAlgorithm("Signature." + mainName, className);
        provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
        provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
        provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);
        if (oid != null)
        {
            provider.addAlgorithm("Alg.Alias.Signature." + oid, mainName);
            provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, mainName);
        }
    }

    protected void addSignatureAlgorithm(
        ConfigurableProvider provider,
        String digest,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid,
        Map<String, String> attributes)
    {
        String mainName = digest + "WITH" + algorithm;
        String jdk11Variation1 = digest + "with" + algorithm;
        String jdk11Variation2 = digest + "With" + algorithm;
        String alias = digest + "/" + algorithm;

        provider.addAlgorithm("Signature." + mainName, className);
        provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
        provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
        provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);
        if (oid != null)
        {
            provider.addAlgorithm("Alg.Alias.Signature." + oid, mainName);
            provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, mainName);
        }
        provider.addAttributes("Signature." + mainName, attributes);
    }

    protected void addKeyPairGeneratorAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid)
    {
        provider.addAlgorithm("KeyPairGenerator." + algorithm, className);
        if (oid != null)
        {
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator." + oid, algorithm);
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.OID." + oid, algorithm);
        }
    }

    protected void addKeyFactoryAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid,
        AsymmetricKeyInfoConverter keyInfoConverter)
    {
        provider.addAlgorithm("KeyFactory." + algorithm, className);
        if (oid != null)
        {
            provider.addAlgorithm("Alg.Alias.KeyFactory." + oid, algorithm);
            provider.addAlgorithm("Alg.Alias.KeyFactory.OID." + oid, algorithm);

            provider.addKeyInfoConverter(oid, keyInfoConverter);
        }
    }

    protected void addKeyGeneratorAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid)
    {
        provider.addAlgorithm("KeyGenerator." + algorithm, className);
        if (oid != null)
        {
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + oid, algorithm);
            provider.addAlgorithm("Alg.Alias.KeyGenerator.OID." + oid, algorithm);
        }
    }

    protected void addCipherAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String className,
        ASN1ObjectIdentifier oid)
    {
        provider.addAlgorithm("Cipher." + algorithm, className);
        if (oid != null)
        {
            provider.addAlgorithm("Alg.Alias.Cipher." + oid, algorithm);
            provider.addAlgorithm("Alg.Alias.Cipher.OID." + oid, algorithm);
        }
    }

    protected void registerKeyFactoryOid(ConfigurableProvider provider, ASN1ObjectIdentifier oid, String name, AsymmetricKeyInfoConverter keyFactory)
    {
        provider.addAlgorithm("Alg.Alias.KeyFactory." + oid, name);
        provider.addAlgorithm("Alg.Alias.KeyFactory.OID." + oid, name);

        provider.addKeyInfoConverter(oid, keyFactory);
    }

    protected void registerOid(ConfigurableProvider provider, ASN1ObjectIdentifier oid, String name, AsymmetricKeyInfoConverter keyFactory)
    {
        provider.addAlgorithm("Alg.Alias.KeyFactory." + oid, name);
        provider.addAlgorithm("Alg.Alias.KeyPairGenerator." + oid, name);

        provider.addKeyInfoConverter(oid, keyFactory);
    }

    protected void registerOidAlgorithmParameters(ConfigurableProvider provider, ASN1ObjectIdentifier oid, String name)
    {
        provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + oid, name);
    }

    protected void registerOidAlgorithmParameterGenerator(ConfigurableProvider provider, ASN1ObjectIdentifier oid, String name)
    {
        provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator." + oid, name);
        provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + oid, name);
    }
}
