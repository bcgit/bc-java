package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

class ECUtils
{
    static AsymmetricKeyParameter generatePrivateKeyParameter(
                PrivateKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECPrivateKey) ? ((BCECPrivateKey)key).engineGetKeyParameters() : ECUtil.generatePrivateKeyParameter(key);
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECPublicKey) ? ((BCECPublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
    }

    static X962Parameters getDomainParametersFromName(ECParameterSpec ecSpec, boolean withCompression)
    {
        X962Parameters params;

        if (ecSpec instanceof ECNamedCurveParameterSpec)
        {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveParameterSpec)ecSpec).getName());

            if (curveOid == null)
            {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveParameterSpec)ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        }
        else if (ecSpec == null)
        {
            params = new X962Parameters(DERNull.INSTANCE);
        }
        else
        {
            ECParameterSpec p = (ECParameterSpec)ecSpec;

            X9ECParameters ecP = new X9ECParameters(
                p.getCurve(), new X9ECPoint(p.getG(), withCompression), p.getN(), p.getH(), p.getSeed());

            params = new X962Parameters(ecP);
        }

        return params;
    }

    static X9ECParameters getDomainParametersFromName(String curveName, ProviderConfiguration configuration)
    {
        if (null == curveName || curveName.length() < 1)
        {
            return null;
        }

        int spacePos = curveName.indexOf(' ');
        if (spacePos > 0)
        {
            curveName = curveName.substring(spacePos + 1);
        }

        ASN1ObjectIdentifier oid = getOID(curveName);
        if (null == oid)
        {
            return ECUtil.getNamedCurveByName(curveName);
        }

        X9ECParameters x9 = ECUtil.getNamedCurveByOid(oid);
        if (null == x9)
        {
            if (null != configuration)
            {
                Map extraCurves = configuration.getAdditionalECParameters();

                x9 = (X9ECParameters)extraCurves.get(oid);
            }
        }

        return x9;
    }

    private static ASN1ObjectIdentifier getOID(String curveName)
    {
        char firstChar = curveName.charAt(0);
        if (firstChar >= '0' && firstChar <= '2')
        {
            try
            {
                return new ASN1ObjectIdentifier(curveName);
            }
            catch (Exception e)
            {
            }
        }
        return null;
    }
}
