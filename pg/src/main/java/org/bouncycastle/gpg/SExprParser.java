package org.bouncycastle.gpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * A parser for secret keys stored in SExpr
 */
public class SExprParser
{
    private final PGPDigestCalculatorProvider digestProvider;

    /**
     * Base constructor.
     *
     * @param digestProvider a provider for digest calculations. Used to confirm key protection hashes.
     */
    public SExprParser(PGPDigestCalculatorProvider digestProvider)
    {
        this.digestProvider = digestProvider;
    }

    /**
     * Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
     *
     * @return a secret key object.
     */
    public PGPSecretKey parseSecretKey(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, PGPPublicKey pubKey)
        throws IOException, PGPException
    {
        SXprUtils.skipOpenParenthesis(inputStream);

        String type;

        type = SXprUtils.readString(inputStream, inputStream.read());
		if (type.equals("protected-private-key")
           || type.equals("private-key"))
        {
            SXprUtils.skipOpenParenthesis(inputStream);

            String keyType = SXprUtils.readString(inputStream, inputStream.read());
            if (keyType.equals("ecc"))
            {
                SXprUtils.skipOpenParenthesis(inputStream);

                String curveID = SXprUtils.readString(inputStream, inputStream.read());
                String curveName = SXprUtils.readString(inputStream, inputStream.read());

                SXprUtils.skipCloseParenthesis(inputStream);

                byte[] qVal;

                SXprUtils.skipOpenParenthesis(inputStream);

                type = SXprUtils.readString(inputStream, inputStream.read());
                if (type.equals("q"))
                {
                    qVal = SXprUtils.readBytes(inputStream, inputStream.read());
                }
                else
                {
                    throw new PGPException("no q value found");
                }

                SXprUtils.skipCloseParenthesis(inputStream);

                BigInteger d = processECSecretKey(inputStream, curveID, curveName, qVal, keyProtectionRemoverFactory);

                if (curveName.startsWith("NIST "))
                {
                    curveName = curveName.substring("NIST ".length());
                }

                ECPublicBCPGKey basePubKey = new ECDSAPublicBCPGKey(ECNamedCurveTable.getOID(curveName), new BigInteger(1, qVal));
                ECPublicBCPGKey assocPubKey = (ECPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                if (!basePubKey.getCurveOID().equals(assocPubKey.getCurveOID())
                    || !basePubKey.getEncodedPoint().equals(assocPubKey.getEncodedPoint()))
                {
                    throw new PGPException("passed in public key does not match secret key");
                }

                return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags.NULL, null, null, new ECSecretBCPGKey(d).getEncoded()), pubKey);
            }
            else if (keyType.equals("dsa"))
            {
                BigInteger p = readBigInteger("p", inputStream);
                BigInteger q = readBigInteger("q", inputStream);
                BigInteger g = readBigInteger("g", inputStream);

                BigInteger y = readBigInteger("y", inputStream);

                BigInteger x = processDSASecretKey(inputStream, p, q, g, y, keyProtectionRemoverFactory);

                DSAPublicBCPGKey basePubKey = new DSAPublicBCPGKey(p, q, g, y);
                DSAPublicBCPGKey assocPubKey = (DSAPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                if (!basePubKey.getP().equals(assocPubKey.getP())
                    || !basePubKey.getQ().equals(assocPubKey.getQ())
                    || !basePubKey.getG().equals(assocPubKey.getG())
                    || !basePubKey.getY().equals(assocPubKey.getY()))
                {
                    throw new PGPException("passed in public key does not match secret key");
                }
                return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags.NULL, null, null, new DSASecretBCPGKey(x).getEncoded()), pubKey);
            }
            else if (keyType.equals("elg"))
            {
                BigInteger p = readBigInteger("p", inputStream);
                BigInteger g = readBigInteger("g", inputStream);

                BigInteger y = readBigInteger("y", inputStream);

                BigInteger x = processElGamalSecretKey(inputStream, p, g, y, keyProtectionRemoverFactory);

                ElGamalPublicBCPGKey basePubKey = new ElGamalPublicBCPGKey(p, g, y);
                ElGamalPublicBCPGKey assocPubKey = (ElGamalPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                if (!basePubKey.getP().equals(assocPubKey.getP())
                    || !basePubKey.getG().equals(assocPubKey.getG())
                    || !basePubKey.getY().equals(assocPubKey.getY()))
                {
                    throw new PGPException("passed in public key does not match secret key");
                }

                return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags.NULL, null, null, new ElGamalSecretBCPGKey(x).getEncoded()), pubKey);
            }
            else if (keyType.equals("rsa"))
            {
                BigInteger n = readBigInteger("n", inputStream);
                BigInteger e = readBigInteger("e", inputStream);

                BigInteger[] values = processRSASecretKey(inputStream, n, e, keyProtectionRemoverFactory);

                // TODO: type of RSA key?
                RSAPublicBCPGKey basePubKey = new RSAPublicBCPGKey(n, e);
                RSAPublicBCPGKey assocPubKey = (RSAPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
                if (!basePubKey.getModulus().equals(assocPubKey.getModulus())
                    || !basePubKey.getPublicExponent().equals(assocPubKey.getPublicExponent()))
                {
                    throw new PGPException("passed in public key does not match secret key");
                }

                return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags.NULL, null, null, new RSASecretBCPGKey(values[0], values[1], values[2]).getEncoded()), pubKey);
            }
            else
            {
                throw new PGPException("unknown key type: " + keyType);
            }
        }

        throw new PGPException("unknown key type found");
    }

    /**
     * Parse a secret key from one of the GPG S expression keys.
     *
     * @return a secret key object.
     */
    public PGPSecretKey parseSecretKey(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        SXprUtils.skipOpenParenthesis(inputStream);

        String type;

        type = SXprUtils.readString(inputStream, inputStream.read());
        if (type.equals("protected-private-key")
            || type.equals("private-key"))
        {
            SXprUtils.skipOpenParenthesis(inputStream);

            String keyType = SXprUtils.readString(inputStream, inputStream.read());
            if (keyType.equals("ecc"))
            {
                SXprUtils.skipOpenParenthesis(inputStream);

                String curveID = SXprUtils.readString(inputStream, inputStream.read());
                String curveName = SXprUtils.readString(inputStream, inputStream.read());

                if (curveName.startsWith("NIST "))
                {
                    curveName = curveName.substring("NIST ".length());
                }

                SXprUtils.skipCloseParenthesis(inputStream);

                byte[] qVal;

                SXprUtils.skipOpenParenthesis(inputStream);

                type = SXprUtils.readString(inputStream, inputStream.read());
                if (type.equals("q"))
                {
                    qVal = SXprUtils.readBytes(inputStream, inputStream.read());
                }
                else
                {
                    throw new PGPException("no q value found");
                }

                PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.ECDSA, new Date(), new ECDSAPublicBCPGKey(ECNamedCurveTable.getOID(curveName), new BigInteger(1, qVal)));

                SXprUtils.skipCloseParenthesis(inputStream);

                BigInteger d = processECSecretKey(inputStream, curveID, curveName, qVal, keyProtectionRemoverFactory);

                return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags.NULL, null, null, new ECSecretBCPGKey(d).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
            }
            else if (keyType.equals("dsa"))
            {
                BigInteger p = readBigInteger("p", inputStream);
                BigInteger q = readBigInteger("q", inputStream);
                BigInteger g = readBigInteger("g", inputStream);

                BigInteger y = readBigInteger("y", inputStream);

                BigInteger x = processDSASecretKey(inputStream, p, q, g, y, keyProtectionRemoverFactory);

                PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.DSA, new Date(), new DSAPublicBCPGKey(p, q, g, y));

                return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags.NULL, null, null, new DSASecretBCPGKey(x).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
            }
            else if (keyType.equals("elg"))
            {
                BigInteger p = readBigInteger("p", inputStream);
                BigInteger g = readBigInteger("g", inputStream);

                BigInteger y = readBigInteger("y", inputStream);

                BigInteger x = processElGamalSecretKey(inputStream, p, g, y, keyProtectionRemoverFactory);

                PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, new Date(), new ElGamalPublicBCPGKey(p, g, y));

                return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags.NULL, null, null, new ElGamalSecretBCPGKey(x).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
            }
            else if (keyType.equals("rsa"))
            {
                BigInteger n = readBigInteger("n", inputStream);
                BigInteger e = readBigInteger("e", inputStream);

                BigInteger[] values = processRSASecretKey(inputStream, n, e, keyProtectionRemoverFactory);

                // TODO: type of RSA key?
                PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), new RSAPublicBCPGKey(n, e));

                return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags.NULL, null, null, new RSASecretBCPGKey(values[0], values[1], values[2]).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
            }
            else
            {
                throw new PGPException("unknown key type: " + keyType);
            }
        }

        throw new PGPException("unknown key type found");
    }

    private BigInteger readBigInteger(String expectedType, InputStream inputStream)
        throws IOException, PGPException
    {
        SXprUtils.skipOpenParenthesis(inputStream);

        String type = SXprUtils.readString(inputStream, inputStream.read());
        if (!type.equals(expectedType))
        {
            throw new PGPException(expectedType + " value expected");
        }

        byte[] nBytes = SXprUtils.readBytes(inputStream, inputStream.read());
        BigInteger v = new BigInteger(1, nBytes);

        SXprUtils.skipCloseParenthesis(inputStream);

        return v;
    }

    private static byte[][] extractData(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws PGPException, IOException
    {
        byte[] data;
        byte[] protectedAt = null;

        SXprUtils.skipOpenParenthesis(inputStream);

        String type = SXprUtils.readString(inputStream, inputStream.read());
        if (type.equals("protected"))
        {
            String protection = SXprUtils.readString(inputStream, inputStream.read());

            SXprUtils.skipOpenParenthesis(inputStream);

            S2K s2k = SXprUtils.parseS2K(inputStream);

            byte[] iv = SXprUtils.readBytes(inputStream, inputStream.read());

            SXprUtils.skipCloseParenthesis(inputStream);

            byte[] secKeyData = SXprUtils.readBytes(inputStream, inputStream.read());

            SXprUtils.skipCloseParenthesis(inputStream);

            PBESecretKeyDecryptor keyDecryptor = keyProtectionRemoverFactory.createDecryptor(protection);

            // TODO: recognise other algorithms
            byte[] key = keyDecryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_128, s2k);

            data = keyDecryptor.recoverKeyData(SymmetricKeyAlgorithmTags.AES_128, key, iv, secKeyData, 0, secKeyData.length);

            // check if protected at is present
            if (inputStream.read() == '(')
            {
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                bOut.write('(');
                int ch;
                while ((ch = inputStream.read()) >= 0 && ch != ')')
                {
                    bOut.write(ch);
                }

                if (ch != ')')
                {
                    throw new IOException("unexpected end to SExpr");
                }

                bOut.write(')');

                protectedAt = bOut.toByteArray();
            }

            SXprUtils.skipCloseParenthesis(inputStream);
            SXprUtils.skipCloseParenthesis(inputStream);
		}
        else if (type.equals("d"))
        {
			return null;
        }
        else
        {
            throw new PGPException("protected block not found");
        }

        return new byte[][]{data, protectedAt};
    }

    private BigInteger processDSASecretKey(InputStream inputStream, BigInteger p, BigInteger q, BigInteger g, BigInteger y,
                                                    PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws IOException, PGPException
    {
        String type;
        byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

        byte[] keyData = basicData[0];
        byte[] protectedAt = basicData[1];

        //
        // parse the secret key S-expr
        //
        InputStream keyIn = new ByteArrayInputStream(keyData);

        SXprUtils.skipOpenParenthesis(keyIn);
        SXprUtils.skipOpenParenthesis(keyIn);

        BigInteger x = readBigInteger("x", keyIn);

        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("hash"))
        {
            throw new PGPException("hash keyword expected");
        }
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("sha1"))
        {
            throw new PGPException("hash keyword expected");
        }

        byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

        SXprUtils.skipCloseParenthesis(keyIn);

        if (digestProvider != null)
        {
            PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags.SHA1);

            OutputStream dOut = digestCalculator.getOutputStream();

            dOut.write(Strings.toByteArray("(3:dsa"));
            writeCanonical(dOut, "p", p);
            writeCanonical(dOut, "q", q);
            writeCanonical(dOut, "g", g);
            writeCanonical(dOut, "y", y);
            writeCanonical(dOut, "x", x);

            // check protected-at
            if (protectedAt != null)
            {
                dOut.write(protectedAt);
            }

            dOut.write(Strings.toByteArray(")"));

            byte[] check = digestCalculator.getDigest();
            if (!Arrays.constantTimeAreEqual(check, hashBytes))
            {
                throw new PGPException("checksum on protected data failed in SExpr");
            }
        }

        return x;
    }

    private BigInteger processElGamalSecretKey(InputStream inputStream, BigInteger p, BigInteger g, BigInteger y,
                                                    PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws IOException, PGPException
    {
        String type;
        byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

        byte[] keyData = basicData[0];
        byte[] protectedAt = basicData[1];

        //
        // parse the secret key S-expr
        //
        InputStream keyIn = new ByteArrayInputStream(keyData);

        SXprUtils.skipOpenParenthesis(keyIn);
        SXprUtils.skipOpenParenthesis(keyIn);

        BigInteger x = readBigInteger("x", keyIn);

        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("hash"))
        {
            throw new PGPException("hash keyword expected");
        }
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("sha1"))
        {
            throw new PGPException("hash keyword expected");
        }

        byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

        SXprUtils.skipCloseParenthesis(keyIn);

        if (digestProvider != null)
        {
            PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags.SHA1);

            OutputStream dOut = digestCalculator.getOutputStream();

            dOut.write(Strings.toByteArray("(3:elg"));
            writeCanonical(dOut, "p", p);
            writeCanonical(dOut, "g", g);
            writeCanonical(dOut, "y", y);
            writeCanonical(dOut, "x", x);

            // check protected-at
            if (protectedAt != null)
            {
                dOut.write(protectedAt);
            }

            dOut.write(Strings.toByteArray(")"));

            byte[] check = digestCalculator.getDigest();
            if (!Arrays.constantTimeAreEqual(check, hashBytes))
            {
                throw new PGPException("checksum on protected data failed in SExpr");
            }
        }

        return x;
    }

    private BigInteger processECSecretKey(InputStream inputStream, String curveID, String curveName, byte[] qVal,
                                             PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws IOException, PGPException
    {
        String type;

        byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

        byte[] keyData = basicData[0];
        byte[] protectedAt = basicData[1];

        //
        // parse the secret key S-expr
        //
        InputStream keyIn = new ByteArrayInputStream(keyData);

        SXprUtils.skipOpenParenthesis(keyIn);
        SXprUtils.skipOpenParenthesis(keyIn);
        BigInteger d = readBigInteger("d", keyIn);
        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);

        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("hash"))
        {
            throw new PGPException("hash keyword expected");
        }
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("sha1"))
        {
            throw new PGPException("hash keyword expected");
        }

        byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

        SXprUtils.skipCloseParenthesis(keyIn);

        if (digestProvider != null)
        {
            PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags.SHA1);

            OutputStream dOut = digestCalculator.getOutputStream();

            dOut.write(Strings.toByteArray("(3:ecc"));

            dOut.write(Strings.toByteArray("(" + curveID.length() + ":" + curveID + curveName.length() + ":" + curveName + ")"));

            writeCanonical(dOut, "q", qVal);
            writeCanonical(dOut, "d", d);

            // check protected-at
            if (protectedAt != null)
            {
                dOut.write(protectedAt);
            }

            dOut.write(Strings.toByteArray(")"));

            byte[] check = digestCalculator.getDigest();

            if (!Arrays.constantTimeAreEqual(check, hashBytes))
            {
                throw new PGPException("checksum on protected data failed in SExpr");
            }
        }

        return d;
    }

    private BigInteger[] processRSASecretKey(InputStream inputStream, BigInteger n, BigInteger e,
                                                    PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws IOException, PGPException
    {
        String type;
        byte[][] basicData = extractData(inputStream, keyProtectionRemoverFactory);

		byte[] keyData;
		byte[] protectedAt = null;

		InputStream keyIn;
		BigInteger d;

		if (basicData == null)
		{
			keyIn = inputStream;
			byte[] nBytes = SXprUtils.readBytes(inputStream,
					inputStream.read());
			d = new BigInteger(1, nBytes);

			SXprUtils.skipCloseParenthesis(inputStream);

		}
		else
		{
			keyData = basicData[0];
			protectedAt = basicData[1];

			keyIn = new ByteArrayInputStream(keyData);

			SXprUtils.skipOpenParenthesis(keyIn);
			SXprUtils.skipOpenParenthesis(keyIn);
			d = readBigInteger("d", keyIn);
		}

        //
        // parse the secret key S-expr
        //

        BigInteger p = readBigInteger("p", keyIn);
        BigInteger q = readBigInteger("q", keyIn);
        BigInteger u = readBigInteger("u", keyIn);

		if (basicData == null)
		{
			return new BigInteger[] { d, p, q, u };
		}

        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("hash"))
        {
            throw new PGPException("hash keyword expected");
        }
        type = SXprUtils.readString(keyIn, keyIn.read());

        if (!type.equals("sha1"))
        {
            throw new PGPException("hash keyword expected");
        }

        byte[] hashBytes = SXprUtils.readBytes(keyIn, keyIn.read());

        SXprUtils.skipCloseParenthesis(keyIn);

        if (digestProvider != null)
        {
            PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags.SHA1);

            OutputStream dOut = digestCalculator.getOutputStream();

            dOut.write(Strings.toByteArray("(3:rsa"));

            writeCanonical(dOut, "n", n);
            writeCanonical(dOut, "e", e);
            writeCanonical(dOut, "d", d);
            writeCanonical(dOut, "p", p);
            writeCanonical(dOut, "q", q);
            writeCanonical(dOut, "u", u);

            // check protected-at
            if (protectedAt != null)
            {
                dOut.write(protectedAt);
            }

            dOut.write(Strings.toByteArray(")"));

            byte[] check = digestCalculator.getDigest();

            if (!Arrays.constantTimeAreEqual(check, hashBytes))
            {
                throw new PGPException("checksum on protected data failed in SExpr");
            }
        }

        return new BigInteger[]{d, p, q, u};
    }

    private void writeCanonical(OutputStream dOut, String label, BigInteger i)
        throws IOException
    {
        writeCanonical(dOut, label, i.toByteArray());
    }

    private void writeCanonical(OutputStream dOut, String label, byte[] data)
        throws IOException
    {
        dOut.write(Strings.toByteArray("(" + label.length() + ":" + label + data.length + ":"));
        dOut.write(data);
        dOut.write(Strings.toByteArray(")"));
    }
}
