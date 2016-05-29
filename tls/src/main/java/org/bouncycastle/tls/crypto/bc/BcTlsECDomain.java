package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsECCUtils;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSignature;
import org.bouncycastle.util.BigIntegers;

public class BcTlsECDomain implements TlsECDomain
{
    protected TlsContext context;
    protected TlsECConfig ecConfig;
    protected ECDomainParameters ecDomain;

    public BcTlsECDomain(TlsContext context, TlsECConfig ecConfig)
    {
        this.context = context;
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

    public TlsSignature createECDSA()
    {
        return new BcTlsECDSA(this);
    }

    public AsymmetricCipherKeyPair generateECKeyPair()
    {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(ecDomain, context.getSecureRandom()));
        return keyPairGenerator.generateKeyPair();
    }

    public ECDomainParameters getParameters(TlsECConfig ecConfig)
    {
        return getParametersForNamedCurve(ecConfig.getNamedCurve());
    }

    public ECDomainParameters getParametersForNamedCurve(int namedCurve)
    {
        String curveName = TlsECCUtils.getNameOfNamedCurve(namedCurve);
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

    public ECPoint readECPoint(InputStream input) throws IOException
    {
        byte[] encoding = TlsUtils.readOpaque8(input);
        return ecDomain.getCurve().decodePoint(encoding);
    }

    public ECPublicKeyParameters readECPublicKey(InputStream input) throws IOException
    {
        try
        {
            ECPoint point = readECPoint(input);

            // TODO Check RFCs for any validation that could/should be done here

            return new ECPublicKeyParameters(point, ecDomain);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public void writeECPoint(ECPoint point, OutputStream output) throws IOException
    {
        TlsUtils.writeOpaque8(point.getEncoded(ecConfig.getPointCompression()), output);
    }

    public void writeECPublicKey(ECPublicKeyParameters publicKey, OutputStream output) throws IOException
    {
        writeECPoint(publicKey.getQ(), output);
    }
}
