package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.NamedCurve;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.util.BigIntegers;

/**
 * EC domain class for generating key pairs and performing key agreement.
 */
public class BcTlsECDomain implements TlsECDomain
{
    protected BcTlsCrypto crypto;
    protected TlsECConfig ecConfig;
    protected ECDomainParameters ecDomain;

    public BcTlsECDomain(BcTlsCrypto crypto, TlsECConfig ecConfig)
    {
        this.crypto = crypto;
        this.ecConfig = ecConfig;
        this.ecDomain = getParameters(ecConfig);
    }

    public byte[] calculateECDHAgreement(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey)
    {
        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);

        /*
         * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
         * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
         * any given field; leading zeros found in this octet string MUST NOT be truncated.
         */
        return BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue);
    }

    public TlsAgreement createECDH()
    {
        return new BcTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] encoding) throws IOException
    {
        return ecDomain.getCurve().decodePoint(encoding);
    }

    public ECPublicKeyParameters decodePublicKey(byte[] encoding) throws IOException
    {
        try
        {
            ECPoint point = decodePoint(encoding);

            // TODO Check RFCs for any validation that could/should be done here

            return new ECPublicKeyParameters(point, ecDomain);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public byte[] encodePoint(ECPoint point) throws IOException
    {
        return point.getEncoded(ecConfig.getPointCompression());
    }

    public byte[] encodePublicKey(ECPublicKeyParameters publicKey) throws IOException
    {
        return encodePoint(publicKey.getQ());
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(ecDomain, crypto.getSecureRandom()));
        return keyPairGenerator.generateKeyPair();
    }

    public BcTlsCrypto getCrypto()
    {
        return crypto;
    }

    public ECDomainParameters getParameters(TlsECConfig ecConfig)
    {
        return getParametersForNamedCurve(ecConfig.getNamedCurve());
    }

    public ECDomainParameters getParametersForNamedCurve(int namedCurve)
    {
        String curveName = NamedCurve.getNameOfSpecificCurve(namedCurve);
        if (curveName == null)
        {
            return null;
        }

        // Parameters are lazily created the first time a particular curve is accessed

        X9ECParameters ecP = CustomNamedCurves.getByName(curveName);
        if (ecP == null)
        {
            ecP = ECNamedCurveTable.getByName(curveName);
            if (ecP == null)
            {
                return null;
            }
        }

        // It's a bit inefficient to do this conversion every time
        return new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }
}
