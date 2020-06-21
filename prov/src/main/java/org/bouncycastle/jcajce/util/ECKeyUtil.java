package org.bouncycastle.jcajce.util;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.ec.CustomNamedCurves;

/**
 * Utility class for EC Keys.
 */
public class ECKeyUtil
{
    /**
     * Convert an ECPublicKey into an ECPublicKey which always encodes
     * with point compression.
     *
     * @param ecPublicKey the originating public key.
     * @return a wrapped version of ecPublicKey which uses point compression.
     */
    public static ECPublicKey createKeyWithCompression(ECPublicKey ecPublicKey)
    {
        return new ECPublicKeyWithCompression(ecPublicKey);
    }

    private static class ECPublicKeyWithCompression
        implements ECPublicKey
    {
        private final ECPublicKey ecPublicKey;

        public ECPublicKeyWithCompression(ECPublicKey ecPublicKey)
        {
            this.ecPublicKey = ecPublicKey;
        }

        public ECPoint getW()
        {
            return ecPublicKey.getW();
        }

        public String getAlgorithm()
        {
            return ecPublicKey.getAlgorithm();
        }

        public String getFormat()
        {
            return ecPublicKey.getFormat();
        }

        public byte[] getEncoded()
        {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(ecPublicKey.getEncoded());

            X962Parameters params = X962Parameters.getInstance(publicKeyInfo.getAlgorithm().getParameters());

            org.bouncycastle.math.ec.ECCurve curve;

            if (params.isNamedCurve())
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)params.getParameters();

                X9ECParameters x9 = CustomNamedCurves.getByOID(oid);
                if (x9 == null)
                {
                    x9 = ECNamedCurveTable.getByOID(oid);
                }
                curve = x9.getCurve();
            }
            else if (params.isImplicitlyCA())
            {
                throw new IllegalStateException("unable to identify implictlyCA");
            }
            else
            {
                X9ECParameters x9 = X9ECParameters.getInstance(params.getParameters());
                curve = x9.getCurve();
            }

            org.bouncycastle.math.ec.ECPoint p = curve.decodePoint(publicKeyInfo.getPublicKeyData().getOctets());
            ASN1OctetString pEnc = ASN1OctetString.getInstance(new X9ECPoint(p,true).toASN1Primitive());

            try
            {
                return new SubjectPublicKeyInfo(publicKeyInfo.getAlgorithm(), pEnc.getOctets()).getEncoded();
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to encode EC public key: " + e.getMessage());
            }
        }

        public ECParameterSpec getParams()
        {
            return ecPublicKey.getParams();
        }
    }
}
