package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;

/**
 * EC domain class for generating key pairs and performing key agreement.
 */
public class JceTlsECDomain
    implements TlsECDomain
{
    protected final JcaTlsCrypto crypto;
    protected final TlsECConfig ecConfig;


    protected ECNamedCurveGenParameterSpec ecGenSpec;
    protected ECParameterSpec ecParameterSpec;
    protected ECCurve ecCurve;

    public JceTlsECDomain(JcaTlsCrypto crypto, TlsECConfig ecConfig)
    {
        this.crypto = crypto;
        this.ecConfig = ecConfig;

        init(ecConfig.getNamedGroup());
    }

    public JceTlsSecret calculateECDHAgreement(ECPrivateKey privateKey, ECPublicKey publicKey)
        throws IOException
    {
        try
        {
            /*
             * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
             * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
             * any given field; leading zeros found in this octet string MUST NOT be truncated.
             *
             * We use the convention established by the JSSE to signal this by asking for "TlsPremasterSecret".
             */
            byte[] secret = crypto.calculateKeyAgreement("ECDH", privateKey, publicKey, "TlsPremasterSecret");

            return crypto.adoptLocalSecret(secret);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    public TlsAgreement createECDH()
    {
        return new JceTlsECDH(this);
    }

    public ECPoint decodePoint(byte[] encoding)
        throws IOException
    {
        return ecCurve.decodePoint(encoding);
    }

    public ECPublicKey decodePublicKey(byte[] encoding)
        throws IOException
    {
        try
        {
            KeyFactory keyFact = crypto.getHelper().createKeyFactory("EC");
            ECPoint point = decodePoint(encoding);
            ECPublicKeySpec keySpec = new ECPublicKeySpec(
                ecParameterSpec.getCurve().createPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger()),
                ecParameterSpec);
            return (ECPublicKey)keyFact.generatePublic(keySpec);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public byte[] encodePoint(ECPoint point)
        throws IOException
    {
        return point.getEncoded(false);
    }

    public byte[] encodePublicKey(ECPublicKey publicKey)
        throws IOException
    {
        ECPoint w = publicKey.getQ();

        return encodePoint(ecCurve.createPoint(w.getAffineXCoord().toBigInteger(), w.getAffineYCoord().toBigInteger()));  // was   ecCurve.createPoint(w.getAffineX(), w.getAffineY()));
    }

    public KeyPair generateKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("EC");
            keyPairGenerator.initialize(ecGenSpec, crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    private void init(int namedGroup)
    {
        this.ecCurve = null;
        this.ecGenSpec = null;
        this.ecParameterSpec = null;

        if (!NamedGroup.refersToASpecificCurve(namedGroup))
        {
            return;
        }

        String curveName = NamedGroup.getName(namedGroup);
        if (curveName == null)
        {
            return;
        }

        try
        {
            AlgorithmParameters ecDomain = crypto.getHelper().createAlgorithmParameters("EC");

            this.ecGenSpec = new ECNamedCurveGenParameterSpec(curveName);

            try
            {
                // Try the "modern" way
                ecDomain.init(ecGenSpec);
                // It's a bit inefficient to do this conversion every time
                ECParameterSpec ecSpec = (ECParameterSpec)ecDomain.getParameterSpec(ECParameterSpec.class);

                this.ecCurve = ecSpec.getCurve(); //  convertCurve(ecSpec.getCurve(), ecSpec.getN(), ecSpec.getH().intValue());
                this.ecParameterSpec = ecSpec;
            }
            catch (Exception e)
            {
                // Try a more round about way (the IBM JCE is an example of this)
                KeyPairGenerator kpGen = crypto.getHelper().createKeyPairGenerator("EC");

                kpGen.initialize(ecGenSpec, crypto.getSecureRandom());

                KeyPair kp = kpGen.generateKeyPair();

                // ECParameterSpec ecSpec = ((ECPrivateKey)kp.getPrivate()).getParams();
                ECParameterSpec ecSpec = (ECParameterSpec)ecDomain.getParameterSpec(ECParameterSpec.class);
                this.ecCurve = ecSpec.getCurve(); //  convertCurve(ecSpec.getCurve(), ecSpec.getOrder(), ecSpec.getCofactor());
                this.ecParameterSpec = ecSpec;
            }
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

//    private static ECCurve convertCurve(EllipticCurve ec, BigInteger order, int cofactor)
//    {
//        ECField field = ec.getField();
//        BigInteger a = ec.getA();
//        BigInteger b = ec.getB();
//
//        if (field instanceof ECFieldFp)
//        {
//            return new ECCurve.Fp(((ECFieldFp)field).getP(), a, b, order, BigInteger.valueOf(cofactor));
//        }
//        else
//        {
//            ECFieldF2m fieldF2m = (ECFieldF2m)field;
//            int m = fieldF2m.getM();
//            int ks[] = convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
//            return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b, order, BigInteger.valueOf(cofactor));
//        }
//    }

    private static int[] convertMidTerms(int[] k)
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
