package org.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.jcajce.io.MacOutputStream;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;

public class JcePKCS12MacCalculatorBuilder
    implements PKCS12MacCalculatorBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private ExtendedDigest digest;
    private ASN1ObjectIdentifier algorithm;

    private SecureRandom random;
    private int saltLength;
    private int iterationCount = 1024;

    public JcePKCS12MacCalculatorBuilder()
    {
        this(OIWObjectIdentifiers.idSHA1);
    }

    public JcePKCS12MacCalculatorBuilder(ASN1ObjectIdentifier hashAlgorithm)
    {
        this.algorithm = hashAlgorithm;
    }

    public JcePKCS12MacCalculatorBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCS12MacCalculatorBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcePKCS12MacCalculatorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;

        return this;
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(algorithm, DERNull.INSTANCE);
    }

    public MacCalculator build(final char[] password)
        throws OperatorCreationException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        try
        {
            final Mac mac = helper.createMac(algorithm.getId());

            saltLength = mac.getMacLength();
            final byte[] salt = new byte[saltLength];

            random.nextBytes(salt);

            SecretKeyFactory keyFact = helper.createSecretKeyFactory(algorithm.getId());
            PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);
            PBEKeySpec pbeSpec = new PBEKeySpec(password);
            SecretKey key = keyFact.generateSecret(pbeSpec);

            mac.init(key, defParams);

            return new MacCalculator()
            {
                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return new AlgorithmIdentifier(algorithm, new PKCS12PBEParams(salt, iterationCount));
                }

                public OutputStream getOutputStream()
                {
                    return new MacOutputStream(mac);
                }

                public byte[] getMac()
                {
                    return mac.doFinal();
                }

                public GenericKey getKey()
                {
                    return new GenericKey(getAlgorithmIdentifier(), PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
                }
            };
        }
        catch (Exception e)
        {
            throw new OperatorCreationException("unable to create MAC calculator: " + e.getMessage(), e);
        }
    }
}
