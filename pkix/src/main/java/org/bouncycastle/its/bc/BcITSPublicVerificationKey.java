package org.bouncycastle.its.bc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.its.ITSPublicVerificationKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point256;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Point384;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

public class BcITSPublicVerificationKey
    extends ITSPublicVerificationKey
{
    public BcITSPublicVerificationKey(PublicVerificationKey verificationKey)
    {
        super(verificationKey);
    }

    static PublicVerificationKey fromKeyParameters(ECPublicKeyParameters pubKey)
    {
        ASN1ObjectIdentifier curveID = ((ECNamedDomainParameters)pubKey.getParameters()).getName();
        ECPoint q = pubKey.getQ();

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaNistP256,
                EccP256CurvePoint.uncompressedP256(
                    Point256.builder()
                        .setX(q.getAffineXCoord().toBigInteger())
                        .setY(q.getAffineYCoord().toBigInteger())
                        .createPoint256()
                ));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP256r1,
                EccP256CurvePoint
                    .uncompressedP256(Point256.builder()
                        .setX(q.getAffineXCoord().toBigInteger())
                        .setY(q.getAffineYCoord().toBigInteger())
                        .createPoint256()));
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new PublicVerificationKey(
                PublicVerificationKey.ecdsaBrainpoolP384r1,
                EccP384CurvePoint.uncompressedP384(Point384.builder()
                    .setX(q.getAffineXCoord().toBigInteger())
                    .setY(q.getAffineYCoord().toBigInteger())
                    .createPoint384()));

        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public BcITSPublicVerificationKey(AsymmetricKeyParameter verificationKey)
    {
        super(fromKeyParameters((ECPublicKeyParameters)verificationKey));
    }

    public AsymmetricKeyParameter getKey()
    {
        X9ECParameters params;
        ASN1ObjectIdentifier curveID;

        switch (verificationKey.getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            curveID = SECObjectIdentifiers.secp256r1;
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP256r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP384r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP384r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }
        ECCurve curve = params.getCurve();

        ASN1Encodable pviCurvePoint = verificationKey.getPublicVerificationKey();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)verificationKey.getPublicVerificationKey();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }

        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        ECPoint point = curve.decodePoint(key).normalize();
        return new ECPublicKeyParameters(point,
            new ECNamedDomainParameters(curveID, params));
    }
}
