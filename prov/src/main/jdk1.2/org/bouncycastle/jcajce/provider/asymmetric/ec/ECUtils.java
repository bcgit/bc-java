package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

class ECUtils
{
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
            ECParameterSpec         p = (ECParameterSpec)ecSpec;

            ECCurve curve = p.getG().getCurve();
            ECPoint generator = curve.createPoint(p.getG().getX().toBigInteger(), p.getG().getY().toBigInteger(), withCompression);

            X9ECParameters ecP = new X9ECParameters(
                p.getCurve(), generator, p.getN(), p.getH(), p.getSeed());

            params = new X962Parameters(ecP);
        }

        return params;
    }
}
