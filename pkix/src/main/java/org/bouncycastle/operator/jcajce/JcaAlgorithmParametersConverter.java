package org.bouncycastle.operator.jcajce;


import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

public class JcaAlgorithmParametersConverter
{
    public JcaAlgorithmParametersConverter()
    {
    }

    public AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier algId, AlgorithmParameters parameters)
        throws CMSException
    {
        try
        {
            ASN1Encodable params = ASN1Primitive.fromByteArray(parameters.getEncoded());

            return new AlgorithmIdentifier(algId, params);
        }
        catch (IOException e)
        {
            throw new CMSException("can't parse parameters", e);
        }
    }

    public AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier algorithm, AlgorithmParameterSpec algorithmSpec)
        throws CMSException
    {
        if (algorithmSpec instanceof OAEPParameterSpec)
        {
            if (algorithmSpec.equals(OAEPParameterSpec.DEFAULT))
            {
                return new AlgorithmIdentifier(algorithm,
                    new RSAESOAEPparams(RSAESOAEPparams.DEFAULT_HASH_ALGORITHM, RSAESOAEPparams.DEFAULT_MASK_GEN_FUNCTION, RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM));
            }
            else
            {
                OAEPParameterSpec oaepSpec = (OAEPParameterSpec)algorithmSpec;
                PSource pSource = oaepSpec.getPSource();

                AlgorithmIdentifier hashAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(oaepSpec.getDigestAlgorithm());
                return new AlgorithmIdentifier(algorithm,
                                    new RSAESOAEPparams(hashAlgorithm, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgorithm),
                                                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(((PSource.PSpecified)pSource).getValue()))));
            }
        }

        throw new IllegalArgumentException("unknown parameter spec passed.");
    }
}
