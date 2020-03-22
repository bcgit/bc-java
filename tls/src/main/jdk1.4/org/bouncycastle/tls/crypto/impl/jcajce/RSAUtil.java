package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
//import java.security.spec.MGF1ParameterSpec;
//import java.security.spec.PSSParameterSpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.HashAlgorithm;

class RSAUtil
{
    static String getDigestSigAlgName(
        String name)
    {
        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }

    static AlgorithmParameterSpec getPSSParameterSpec(short hash, String digestName, JcaJceHelper helper)
    {
// Used where providers can't handle PSSParameterSpec properly.
        AlgorithmIdentifier hashAlg = getHashAlgorithmID(hash);

        RSASSAPSSparams pssParams = new RSASSAPSSparams(
            hashAlg,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlg),
            new ASN1Integer(HashAlgorithm.getOutputSize(hash)),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);


        try
        {
            AlgorithmParameters params = helper.createAlgorithmParameters("PSS");

            params.init(pssParams.getEncoded(), "ASN.1");

            return params.getParameterSpec(AlgorithmParameterSpec.class);
        }
        catch (IOException e)
        {   // this should never happen!
            throw new IllegalStateException("cannot encode RSASSAPSSparams: " + e.getMessage());
        }
        catch (InvalidParameterSpecException e)
        {
            throw new IllegalStateException("cannot recover PSS paramSpec: " + e.getMessage());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("cannot recover PSS paramSpec: " + e.getMessage());
        }
        catch (NoSuchProviderException e)
        {
            throw new IllegalStateException("cannot recover PSS paramSpec: " + e.getMessage());
        }

//        MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(digestName);
//        return new PSSParameterSpec(digestName, "MGF1", mgf1Spec, HashAlgorithm.getOutputSize(hash), 1);
    }

    private static AlgorithmIdentifier getHashAlgorithmID(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.sha256:
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        case HashAlgorithm.sha384:
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        case HashAlgorithm.sha512:
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
        default:
            return null;
        }
    }
}
