package org.bouncycastle.gpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
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
        if (type.equals("protected-private-key"))
        {
            SXprUtils.skipOpenParenthesis(inputStream);

            String curveID;
            String curveName;

            String keyType = SXprUtils.readString(inputStream, inputStream.read());
            if (keyType.equals("ecc"))
            {
                SXprUtils.skipOpenParenthesis(inputStream);

                curveID = SXprUtils.readString(inputStream, inputStream.read());
                curveName = SXprUtils.readString(inputStream, inputStream.read());

                SXprUtils.skipCloseParenthesis(inputStream);
            }
            else
            {
                throw new PGPException("no curve details found");
            }

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

            byte[] dValue = processECSecretKey(inputStream, curveID, curveName, qVal, keyProtectionRemoverFactory);

            return new PGPSecretKey(new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags.NULL, null, null, new ECSecretBCPGKey(new BigInteger(1, dValue)).getEncoded()), pubKey);
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
        if (type.equals("protected-private-key"))
        {
            SXprUtils.skipOpenParenthesis(inputStream);

            String curveName;

            String keyType = SXprUtils.readString(inputStream, inputStream.read());
            if (keyType.equals("ecc"))
            {
                SXprUtils.skipOpenParenthesis(inputStream);

                String curveID = SXprUtils.readString(inputStream, inputStream.read());
                curveName = SXprUtils.readString(inputStream, inputStream.read());

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

                byte[] dValue = processECSecretKey(inputStream, curveID, curveName, qVal, keyProtectionRemoverFactory);

                return new PGPSecretKey(new SecretKeyPacket(pubPacket, SymmetricKeyAlgorithmTags.NULL, null, null, new ECSecretBCPGKey(new BigInteger(1, dValue)).getEncoded()), new PGPPublicKey(pubPacket, fingerPrintCalculator));
            }
            else if (keyType.equals("rsa"))
            {
                SXprUtils.skipOpenParenthesis(inputStream);

                type = SXprUtils.readString(inputStream, inputStream.read());
                if (!type.equals("n"))
                {
                    throw new PGPException("n value expected");
                }
                byte[] nBytes = SXprUtils.readBytes(inputStream, inputStream.read());
                BigInteger n = new BigInteger(1, nBytes);
                SXprUtils.skipCloseParenthesis(inputStream);

                SXprUtils.skipOpenParenthesis(inputStream);

                type = SXprUtils.readString(inputStream, inputStream.read());
                if (!type.equals("e"))
                {
                    throw new PGPException("e value expected");
                }
                byte[] eBytes = SXprUtils.readBytes(inputStream, inputStream.read());
                BigInteger e = new BigInteger(1, eBytes);

                SXprUtils.skipCloseParenthesis(inputStream);

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
        else
        {
            throw new PGPException("protected block not found");
        }

        return new byte[][]{data, protectedAt};
    }

    private byte[] processECSecretKey(InputStream inputStream, String curveID, String curveName, byte[] qVal,
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
        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());
        if (!type.equals("d"))
        {
            throw new PGPException("d value expected");
        }
        byte[] d = SXprUtils.readBytes(keyIn, keyIn.read());

        SXprUtils.skipCloseParenthesis(keyIn);
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

            dOut.write(Strings.toByteArray("(1:q" + qVal.length + ":"));
            dOut.write(qVal);
            dOut.write(Strings.toByteArray(")"));

            dOut.write(Strings.toByteArray("(1:d" + d.length + ":"));
            dOut.write(d);
            dOut.write(Strings.toByteArray(")"));

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

        byte[] keyData = basicData[0];
        byte[] protectedAt = basicData[1];

        //
        // parse the secret key S-expr
        //
        InputStream keyIn = new ByteArrayInputStream(keyData);

        SXprUtils.skipOpenParenthesis(keyIn);
        SXprUtils.skipOpenParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());
        if (!type.equals("d"))
        {
            throw new PGPException("d value expected");
        }
        byte[] dBytes = SXprUtils.readBytes(keyIn, keyIn.read());
        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());
        if (!type.equals("p"))
        {
            throw new PGPException("p value expected");
        }
        byte[] pBytes = SXprUtils.readBytes(keyIn, keyIn.read());
        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);
        type = SXprUtils.readString(keyIn, keyIn.read());
        if (!type.equals("q"))
        {
            throw new PGPException("q value expected");
        }
        byte[] qBytes = SXprUtils.readBytes(keyIn, keyIn.read());
        SXprUtils.skipCloseParenthesis(keyIn);

        SXprUtils.skipOpenParenthesis(keyIn);

        type = SXprUtils.readString(keyIn, keyIn.read());
        if (!type.equals("u"))
        {
            throw new PGPException("u value expected");
        }

        byte[] uBytes = SXprUtils.readBytes(keyIn, keyIn.read());
        SXprUtils.skipCloseParenthesis(keyIn);
        SXprUtils.skipCloseParenthesis(keyIn);

        BigInteger d = new BigInteger(1, dBytes);
        BigInteger p = new BigInteger(1, pBytes);
        BigInteger q = new BigInteger(1, qBytes);
        BigInteger u = new BigInteger(1, uBytes);

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
            dOut.write(Strings.toByteArray("(1:n" + n.toByteArray().length + ":"));
            dOut.write(n.toByteArray());
            dOut.write(Strings.toByteArray(")"));
            dOut.write(Strings.toByteArray("(1:e" + e.toByteArray().length + ":"));
            dOut.write(e.toByteArray());
            dOut.write(Strings.toByteArray(")"));
            dOut.write(Strings.toByteArray("(1:d" + d.toByteArray().length + ":"));
            dOut.write(d.toByteArray());
            dOut.write(Strings.toByteArray(")"));
            dOut.write(Strings.toByteArray("(1:p" + p.toByteArray().length + ":"));
            dOut.write(p.toByteArray());
            dOut.write(Strings.toByteArray(")"));
            dOut.write(Strings.toByteArray("(1:q" + q.toByteArray().length + ":"));
            dOut.write(q.toByteArray());
            dOut.write(Strings.toByteArray(")"));
            dOut.write(Strings.toByteArray("(1:u" + u.toByteArray().length + ":"));
            dOut.write(u.toByteArray());
            dOut.write(Strings.toByteArray(")"));

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
}
