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
import org.bouncycastle.tls.NamedGroup;
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
    public int getPublicKeyByteLength()
    {
        return (((domainParameters.getCurve().getFieldSize() + 7) / 8) * 2) + 1;
    }

    public byte[] calculateECDHAgreementBytes(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
    {
        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);
        return BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue);
    }
    
    public static BcTlsSecret calculateECDHAgreement(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey,
        ECPublicKeyParameters publicKey)
    {
        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);

        /*
         * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
         * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
         * any given field; leading zeros found in this octet string MUST NOT be truncated.
         */
        byte[] secret = BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue);
        return crypto.adoptLocalSecret(secret);
    }

    public static ECDomainParameters getDomainParameters(TlsECConfig ecConfig)
    {
        ECDomainParameters parameters = getDomainParameters(ecConfig.getNamedGroup());
        if (parameters == null)
        {
            throw new IllegalArgumentException("No EC configuration provided");
        }

        return parameters;
    }

    public static ECDomainParameters getDomainParameters(int namedGroup)
    {
        if (!NamedGroup.refersToASpecificCurve(namedGroup))
        {
            return null;
        }

        // Parameters are lazily created the first time a particular curve is accessed

        String curveName = NamedGroup.getCurveName(namedGroup);
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
    
    protected final BcTlsCrypto crypto;
    protected final TlsECConfig config;
    protected final ECDomainParameters domainParameters;

    public BcTlsECDomain(BcTlsCrypto crypto, TlsECConfig ecConfig)
    {
        this.crypto = crypto;
        this.config = ecConfig;
        this.domainParameters = getDomainParameters(ecConfig);
    }

    public BcTlsSecret calculateECDHAgreement(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
    {
        return calculateECDHAgreement(crypto, privateKey, publicKey);
    }

    public TlsAgreement createECDH()
    {
        return new BcTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] encoding)
    {
        return domainParameters.getCurve().decodePoint(encoding);
    }

    public ECPublicKeyParameters decodePublicKey(byte[] encoding) throws IOException
    {
        try
        {
            ECPoint point = decodePoint(encoding);

            return new ECPublicKeyParameters(point, domainParameters);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public byte[] encodePoint(ECPoint point)
    {
        return point.getEncoded(false);
    }

    public byte[] encodePublicKey(ECPublicKeyParameters publicKey)
    {
        return encodePoint(publicKey.getQ());
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(domainParameters, crypto.getSecureRandom()));
        return keyPairGenerator.generateKeyPair();
    }
}
