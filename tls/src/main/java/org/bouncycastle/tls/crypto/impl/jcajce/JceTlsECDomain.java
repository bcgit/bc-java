package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.NamedCurve;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;

/**
 * EC domain class for generating key pairs and performing key agreement.
 */
public class JceTlsECDomain
    implements TlsECDomain
{
    protected JcaTlsCrypto crypto;
    protected TlsECConfig ecConfig;
    protected AlgorithmParameters ecDomain;
    protected ECCurve ecCurve;

    public JceTlsECDomain(JcaTlsCrypto crypto, TlsECConfig ecConfig)
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

    public byte[] encodePublicKey(ECPublicKey publicKey) throws IOException
    {
        java.security.spec.ECPoint w = publicKey.getW();

        return encodePoint(ecCurve.createPoint(w.getAffineX(), w.getAffineY()));
    }

    public KeyPair generateKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("EC");
            keyPairGenerator.initialize(ecDomain.getParameterSpec(ECGenParameterSpec.class), crypto.getSecureRandom());
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

        try
        {
            this.ecDomain  = crypto.getHelper().createAlgorithmParameters("EC");

            this.ecDomain.init(new ECGenParameterSpec(curveName));
            // It's a bit inefficient to do this conversion every time
            ECParameterSpec ecSpec = this.ecDomain.getParameterSpec(ECParameterSpec.class);

            this.ecCurve = convertCurve(ecSpec.getCurve(), ecSpec.getOrder(), ecSpec.getCofactor());
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    private static ECCurve convertCurve(
        EllipticCurve ec,
        BigInteger order,
        int cofactor)
    {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();

        if (field instanceof ECFieldFp)
        {
            ECCurve.Fp curve = new ECCurve.Fp(((ECFieldFp)field).getP(), a, b, order, BigInteger.valueOf(cofactor));

            return curve;
        }
        else
        {
            ECFieldF2m fieldF2m = (ECFieldF2m)field;
            int m = fieldF2m.getM();
            int ks[] = convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
            return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b, order, BigInteger.valueOf(cofactor));
        }
    }

    private static int[] convertMidTerms(
        int[] k)
    {
        int[] res = new int[3];

        if (k.length == 1)
        {
            res[0] = k[0];
        }
        else
        {
            if (k.length != 3)
            {
                throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
            }

            if (k[0] < k[1] && k[0] < k[2])
            {
                res[0] = k[0];
                if (k[1] < k[2])
                {
                    res[1] = k[1];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            }
            else if (k[1] < k[2])
            {
                res[0] = k[1];
                if (k[0] < k[2])
                {
                    res[1] = k[0];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            }
            else
            {
                res[0] = k[2];
                if (k[0] < k[1])
                {
                    res[1] = k[0];
                    res[2] = k[1];
                }
                else
                {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }

}
