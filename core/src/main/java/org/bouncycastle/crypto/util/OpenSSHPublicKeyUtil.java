package org.bouncycastle.crypto.util;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.math.ec.ECCurve;

import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.Strings;


public class OpenSSHPublicKeyUtil
{
    private OpenSSHPublicKeyUtil()
    {

    }

    public static final String RSA = "ssh-rsa";
    public static final String ECDSA = "ecdsa";
    public static final String ED_25519 = "ssh-ed25519";
    private static final String DSS = "ssh-dss";

    public static CipherParameters parsePublicKey(byte[] encoded)
    {
        SSHBuffer buffer = new SSHBuffer(encoded);
        return parsePublicKey(buffer);
    }

    public static byte[] encodePublicKey(CipherParameters cipherParameters)
    {
        BigInteger e;
        BigInteger n;

        if (cipherParameters == null)
        {
            throw new IllegalArgumentException("cipherParameters was null.");
        }

        if (cipherParameters instanceof RSAKeyParameters)
        {
            if (((RSAKeyParameters)cipherParameters).isPrivate())
            {
                throw new IllegalArgumentException("RSAKeyParamaters was for encryption");
            }

            e = ((RSAKeyParameters)cipherParameters).getExponent();
            n = ((RSAKeyParameters)cipherParameters).getModulus();

            SSHBuilder builder = new SSHBuilder();
            builder.writeString(RSA);
            builder.rawArray(e.toByteArray());
            builder.rawArray(n.toByteArray());

            return builder.getBytes();

        }
        else if (cipherParameters instanceof ECPublicKeyParameters)
        {
            SSHBuilder builder = new SSHBuilder();

            String name = null;
            if (((ECPublicKeyParameters)cipherParameters).getParameters().getCurve() instanceof SecP256R1Curve)
            {
                name = "nistp256";
            }
            else
            {
                throw new IllegalArgumentException("unable to derive ssh curve name for " + ((ECPublicKeyParameters)cipherParameters).getParameters().getCurve().getClass().getName());
            }

            builder.writeString(ECDSA + "-sha2-" + name); // Magic
            builder.writeString(name);
            builder.rawArray(((ECPublicKeyParameters)cipherParameters).getQ().getEncoded(false)); //Uncompressed
            return builder.getBytes();
        }
        else if (cipherParameters instanceof DSAPublicKeyParameters)
        {
            SSHBuilder builder = new SSHBuilder();
            builder.writeString(DSS);
            builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getParameters().getP().toByteArray());
            builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getParameters().getQ().toByteArray());
            builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getParameters().getG().toByteArray());
            builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getY().toByteArray());
            return builder.getBytes();
        }
        else if (cipherParameters instanceof Ed25519PublicKeyParameters)
        {
            SSHBuilder builder = new SSHBuilder();
            builder.writeString(ED_25519);
            builder.rawArray(((Ed25519PublicKeyParameters)cipherParameters).getEncoded());
            return builder.getBytes();
        }

        throw new IllegalArgumentException("unable to convert " + cipherParameters.getClass().getName() + " to private key");
    }


    public static CipherParameters parsePublicKey(SSHBuffer buffer)
    {
        CipherParameters result = null;

        String magic = Strings.fromByteArray(buffer.readString());
        if (RSA.equals(magic))
        {
            BigInteger e = buffer.positiveBigNum();
            BigInteger n = buffer.positiveBigNum();
            result = new RSAKeyParameters(false, n, e);
        }
        else if (DSS.equals(magic))
        {
            BigInteger p = buffer.positiveBigNum();
            BigInteger q = buffer.positiveBigNum();
            BigInteger g = buffer.positiveBigNum();
            BigInteger pubKey = buffer.positiveBigNum();

            result = new DSAPublicKeyParameters(pubKey, new DSAParameters(p, q, g));
        }
        else if (magic.startsWith(ECDSA))
        {
            String curveName = Strings.fromByteArray(buffer.readString());
            String nameToFind = curveName;

            if (curveName.startsWith("nist"))
            {
                //
                // NIST names like P-256 are encoded in SSH as nistp256
                //

                nameToFind = curveName.substring(4);
                nameToFind = nameToFind.substring(0, 1) + "-" + nameToFind.substring(1);
            }

            X9ECParameters x9ECParameters = ECNamedCurveTable.getByName(nameToFind);

            if (x9ECParameters == null)
            {
                throw new IllegalStateException("unable to find curve for " + magic + " using curve name " + nameToFind);
            }

            //
            // Extract name of digest from magic string value;
            //
            //String digest = magic.split("-")[1];

            ECCurve curve = x9ECParameters.getCurve();

            byte[] pointRaw = buffer.readString();

            result = new ECPublicKeyParameters(curve.decodePoint(pointRaw), new ECDomainParameters(curve, x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed()));
        }
        else if (magic.startsWith(ED_25519))
        {
            result = new Ed25519PublicKeyParameters(buffer.readString(), 0);
        }

        if (result == null)
        {
            throw new IllegalArgumentException("unable to parse key");
        }

        if (buffer.hasRemaining())
        {
            throw new IllegalArgumentException("uncoded key has trailing data");
        }

        return result;
    }
}
