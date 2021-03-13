package org.bouncycastle.operator.jcajce;


import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

public class JcaAlgorithmParametersConverter
{
    public JcaAlgorithmParametersConverter()
    {
    }

    public AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier algId, AlgorithmParameters parameters)
        throws InvalidAlgorithmParameterException
    {
        try
        {
            ASN1Encodable params = ASN1Primitive.fromByteArray(parameters.getEncoded());

            return new AlgorithmIdentifier(algId, params);
        }
        catch (IOException e)
        {
            throw new InvalidAlgorithmParameterException("unable to encode parameters object: " + e.getMessage());
        }
    }

    public AlgorithmIdentifier getAlgorithmIdentifier(ASN1ObjectIdentifier algorithm, AlgorithmParameterSpec algorithmSpec)
        throws InvalidAlgorithmParameterException
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

                if (!oaepSpec.getMGFAlgorithm().equals(OAEPParameterSpec.DEFAULT.getMGFAlgorithm()))
                {
                    throw new InvalidAlgorithmParameterException("only " + OAEPParameterSpec.DEFAULT.getMGFAlgorithm() + " mask generator supported.");
                }

                AlgorithmIdentifier hashAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(oaepSpec.getDigestAlgorithm());
                if (hashAlgorithm.getParameters() == null) {
                    hashAlgorithm = new AlgorithmIdentifier(hashAlgorithm.getAlgorithm(), DERNull.INSTANCE);
                }
                AlgorithmIdentifier mgf1HashAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find((((MGF1ParameterSpec)oaepSpec.getMGFParameters()).getDigestAlgorithm()));
                if (mgf1HashAlgorithm.getParameters() == null) {
                    mgf1HashAlgorithm = new AlgorithmIdentifier(mgf1HashAlgorithm.getAlgorithm(), DERNull.INSTANCE);
                }
                return new AlgorithmIdentifier(algorithm,
                                    new RSAESOAEPparams(hashAlgorithm, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgf1HashAlgorithm),
                                                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(((PSource.PSpecified)pSource).getValue()))));
            }
        }

        throw new InvalidAlgorithmParameterException("unknown parameter spec passed.");
    }
}
