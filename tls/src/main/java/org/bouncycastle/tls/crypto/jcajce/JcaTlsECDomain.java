package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.NamedCurve;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSignature;

public class JcaTlsECDomain
    implements TlsECDomain
{
    protected JcaTlsCrypto crypto;
    protected TlsECConfig ecConfig;
    protected AlgorithmParameters ecDomain;
    protected ECCurve ecCurve;

    public JcaTlsECDomain(JcaTlsCrypto crypto, TlsECConfig ecConfig)
    {
        this.crypto = crypto;
        this.ecConfig = ecConfig;

        init(ecConfig.getNamedCurve());
    }

    public byte[] calculateECDHAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = crypto.getHelper().createKeyAgreement("ECDH");

        agreement.init(privateKey);

        agreement.doPhase(publicKey, true);

        /*
         * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
         * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
         * any given field; leading zeros found in this octet string MUST NOT be truncated.
         *
         * We use the convention established by the JSSE to signal this by asking for "TlsPremasterSecret".
         */
        return agreement.generateSecret("TlsPremasterSecret").getEncoded();
    }

    public TlsAgreement createECDH()
    {
        return new JceTlsECDH(this);
    }

    public TlsSignature createECDSA()
    {
        return new JcaTlsECDSA(this);
    }

    public ECPoint decodePoint(byte[] encoding) throws IOException
    {
        return ecCurve.decodePoint(encoding);
    }

    public ECPublicKey decodePublicKey(byte[] encoding) throws IOException
    {
        try
        {
            KeyFactory keyFact = crypto.getHelper().createKeyFactory("EC");
            ECPoint point = decodePoint(encoding);
            ECPublicKeySpec keySpec = new ECPublicKeySpec(
                new java.security.spec.ECPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger()),
                ecDomain.getParameterSpec(ECParameterSpec.class));
            // TODO Check RFCs for any validation that could/should be done here

            return (ECPublicKey)keyFact.generatePublic(keySpec);
        }
        catch (Exception e)
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

    public KeyPair generateKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("EC");
            keyPairGenerator.initialize(ecDomain.getParameterSpec(ECGenParameterSpec.class), crypto.getContext().getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    public JcaTlsCrypto getCrypto()
    {
        return crypto;
    }

    private void init(int namedCurve)
    {
        this.ecCurve = null;
        this.ecDomain = null;

        String curveName = NamedCurve.getNameOfSpecificCurve(namedCurve);
        if (curveName == null)
        {
             return;
        }

        X9ECParameters ecP = CustomNamedCurves.getByName(curveName);
        if (ecP == null)
        {
            ecP = ECNamedCurveTable.getByName(curveName);
            if (ecP == null)
            {
                return;
            }
        }

        this.ecCurve = ecP.getCurve();

        try
        {
            this.ecDomain  = crypto.getHelper().createAlgorithmParameters("EC");
            this.ecDomain .init(new ECGenParameterSpec(curveName));
            // It's a bit inefficient to do this conversion every time
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}
