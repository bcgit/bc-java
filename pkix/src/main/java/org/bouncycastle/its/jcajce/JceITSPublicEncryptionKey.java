package org.bouncycastle.its.jcajce;

import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.its.ITSPublicEncryptionKey;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.BasePublicEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SymmAlgorithm;

public class JceITSPublicEncryptionKey
    extends ITSPublicEncryptionKey
{
    private final JcaJceHelper helper;

    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JceITSPublicEncryptionKey build(PublicEncryptionKey encryptionKey)
        {
            return new JceITSPublicEncryptionKey(encryptionKey, helper);
        }

        public JceITSPublicEncryptionKey build(PublicKey encryptionKey)
        {
            return new JceITSPublicEncryptionKey(encryptionKey, helper);
        }
    }

    JceITSPublicEncryptionKey(PublicEncryptionKey encryptionKey, JcaJceHelper helper)
    {
        super(encryptionKey);
        this.helper = helper;
    }

    JceITSPublicEncryptionKey(PublicKey encryptionKey, JcaJceHelper helper)
    {
        super(fromPublicKey(encryptionKey));
        this.helper = helper;
    }

    static PublicEncryptionKey fromPublicKey(PublicKey key)
    {
        if (!(key instanceof ECPublicKey))
        {
            throw new IllegalArgumentException("must be ECPublicKey instance");
        }

        ECPublicKey pKey = (ECPublicKey)key;

        ASN1ObjectIdentifier curveID = ASN1ObjectIdentifier.getInstance(
            SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm().getParameters());

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicEncryptionKey(
                SymmAlgorithm.aes128Ccm,
                new BasePublicEncryptionKey.Builder()
                    .setChoice(BasePublicEncryptionKey.eciesNistP256)
                    .setValue(EccP256CurvePoint
                        .uncompressedP256(
                            pKey.getW().getAffineX(),
                            pKey.getW().getAffineY()))
                    .createBasePublicEncryptionKey());
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicEncryptionKey(
                SymmAlgorithm.aes128Ccm,
                new BasePublicEncryptionKey.Builder()
                    .setChoice(BasePublicEncryptionKey.eciesBrainpoolP256r1)
                    .setValue(EccP256CurvePoint
                        .uncompressedP256(
                            pKey.getW().getAffineX(),
                            pKey.getW().getAffineY()))
                    .createBasePublicEncryptionKey());
        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }

    }

    public PublicKey getKey()
    {
        BasePublicEncryptionKey baseKey = encryptionKey.getPublicKey();
        X9ECParameters params;

        switch (baseKey.getChoice())
        {
        case BasePublicEncryptionKey.eciesNistP256:

            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case BasePublicEncryptionKey.eciesBrainpoolP256r1:
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }

        ASN1Encodable pviCurvePoint = encryptionKey.getPublicKey().getBasePublicEncryptionKey();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)baseKey.getBasePublicEncryptionKey();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }
        ECCurve curve = params.getCurve();

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

        try
        {
            KeyFactory keyFactory = helper.createKeyFactory("EC");
            ECParameterSpec spec = ECUtil.convertToSpec(params);
            java.security.spec.ECPoint jPoint = ECUtil.convertPoint(point);
            return keyFactory.generatePublic(new ECPublicKeySpec(jPoint, spec));
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }
}
