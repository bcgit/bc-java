package org.bouncycastle.gpg;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
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
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;
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

    private static final Map<Integer, String[]> rsaLabels = new HashMap<Integer, String[]>()
    {{
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_OCB_AES), new String[]{"rsa", "n", "e", "protected-at"});
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC), new String[]{"rsa", "n", "e", "d", "p", "q", "u", "protected-at"});
    }};
    private static final Map<Integer, String[]> eccLabels = new HashMap<Integer, String[]>()
    {{
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_OCB_AES), new String[]{"ecc", "curve", "flags", "q", "protected-at"});
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC), new String[]{"ecc", "curve", "q", "d", "protected-at"});
    }};

    private static final Map<Integer, String[]> dsaLabels = new HashMap<Integer, String[]>()
    {{
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_OCB_AES), new String[]{"dsa", "p", "q", "g", "y", "protected-at"});
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC), new String[]{"dsa", "p", "q", "g", "y", "x", "protected-at"});
    }};

    private static final Map<Integer, String[]> elgLabels = new HashMap<Integer, String[]>()
    {{
        //https://github.com/gpg/gnupg/blob/40227e42ea0f2f1cf9c9f506375446648df17e8d/agent/cvt-openpgp.c#L217
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_OCB_AES), new String[]{"elg", "p", "q", "g", "y", "protected-at"});
        put(Integers.valueOf(ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC), new String[]{"elg", "p", "q", "g", "y", "x", "protected-at"});
    }};

    private static final String[] rsaBigIntegers = new String[]{"n", "e"};
    private static final String[] dsaBigIntegers = new String[]{"p", "q", "g", "y"};
    private static final String[] elgBigIntegers = new String[]{"p", "g", "y"};

    public interface ProtectionFormatTypeTags
    {
        int PRIVATE_KEY = 1;
        int PROTECTED_PRIVATE_KEY = 2;
        int SHADOWED_PRIVATE_KEY = 3;
        int OPENPGP_PRIVATE_KEY = 4;
        int PROTECTED_SHARED_SECRET = 5;
    }

    private interface ProtectionModeTags
    {
        int OPENPGP_S2K3_SHA1_AES_CBC = 1;
        int OPENPGP_S2K3_OCB_AES = 2;
        int OPENPGP_NATIVE = 3;
    }

    /**
     * Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
     *
     * @return a secret key object.
     */
    public PGPSecretKey parseSecretKey(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, PGPPublicKey pubKey)
        throws IOException, PGPException
    {
        if (pubKey == null)
        {
            throw new NullPointerException("Public key cannot be null");
        }
        return parse(inputStream, keyProtectionRemoverFactory, null, pubKey);
    }

    /**
     * Parse a secret key from one of the GPG S expression keys.
     *
     * @return a secret key object.
     */
    public PGPSecretKey parseSecretKey(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory,
                                       KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        return parse(inputStream, keyProtectionRemoverFactory, fingerPrintCalculator, null);
    }

    private PGPSecretKey parse(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory,
                               KeyFingerPrintCalculator fingerPrintCalculator, PGPPublicKey pubKey)
        throws IOException, PGPException
    {
        final int maxDepth = 10;
        SExpression keyExpression = SExpression.parseCanonical(inputStream, maxDepth);
        int type = getProtectionType(keyExpression.getString(0));
        if (type == ProtectionFormatTypeTags.PRIVATE_KEY || type == ProtectionFormatTypeTags.PROTECTED_PRIVATE_KEY ||
            type == ProtectionFormatTypeTags.SHADOWED_PRIVATE_KEY)
        {
            SExpression expression = keyExpression.getExpression(1);
            String keyType = expression.getString(0);
            PublicKeyAlgorithmTags[] secretKey = getPGPSecretKey(keyProtectionRemoverFactory, fingerPrintCalculator,
                pubKey, maxDepth, type, expression, keyType, digestProvider);
            return new PGPSecretKey((SecretKeyPacket)secretKey[0], (PGPPublicKey)secretKey[1]);
        }
        throw new PGPException("unknown key type found");
    }

    public static PublicKeyAlgorithmTags[] getPGPSecretKey(PBEProtectionRemoverFactory keyProtectionRemoverFactory,
                                                           KeyFingerPrintCalculator fingerPrintCalculator, PGPPublicKey pubKey,
                                                           int maxDepth, int type, final SExpression expression, String keyType,
                                                           PGPDigestCalculatorProvider digestProvider)
        throws PGPException, IOException
    {
        SecretKeyPacket secretKeyPacket;
        if (keyType.equals("ecc"))
        {
            BCPGKey basePubKey = getECCBasePublicKey(expression);
            if (pubKey != null)
            {
                assertEccPublicKeyMath(basePubKey, pubKey);
            }
            else
            {
                PublicKeyPacket pubPacket = null;
                if (basePubKey instanceof EdDSAPublicBCPGKey)
                {
                    pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.EDDSA_LEGACY, new Date(), basePubKey);
                }
                else if (basePubKey instanceof ECPublicBCPGKey)
                {
                    pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.ECDSA, new Date(), basePubKey);
                }
                pubKey = new PGPPublicKey(pubPacket, fingerPrintCalculator);
            }
            secretKeyPacket = getSecKeyPacket(pubKey, keyProtectionRemoverFactory, maxDepth, type, expression, digestProvider, eccLabels,
                new getSecKeyDataOperation()
                {
                    @Override
                    public byte[] getSecKeyData(SExpression keyIn)
                    {
                        BigInteger d = BigIntegers.fromUnsignedByteArray(keyIn.getExpressionWithLabelOrFail("d").getBytes(1));
                        final String curve = expression.getExpressionWithLabel("curve").getString(1);
                        if (curve.startsWith("NIST") || curve.startsWith("brain"))
                        {
                            return new ECSecretBCPGKey(d).getEncoded();
                        }
                        else
                        {
                            return new EdSecretBCPGKey(d).getEncoded();
                        }
                    }
                });
        }
        else if (keyType.equals("dsa"))
        {
            pubKey = getPublicKey(fingerPrintCalculator, pubKey, expression, PublicKeyAlgorithmTags.DSA, dsaBigIntegers, new getPublicKeyOperation()
            {
                public BCPGKey getBasePublicKey(BigInteger[] bigIntegers)
                {
                    return new DSAPublicBCPGKey(bigIntegers[0], bigIntegers[1], bigIntegers[2], bigIntegers[3]);
                }

                public void assertPublicKeyMatch(BCPGKey k1, BCPGKey k2)
                    throws PGPException
                {
                    DSAPublicBCPGKey key1 = (DSAPublicBCPGKey)k1;
                    DSAPublicBCPGKey key2 = (DSAPublicBCPGKey)k2;
                    if (!key1.getP().equals(key2.getP()) || !key1.getQ().equals(key2.getQ())
                        || !key1.getG().equals(key2.getG()) || !key1.getY().equals(key2.getY()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }
            });
            secretKeyPacket = getSecKeyPacket(pubKey, keyProtectionRemoverFactory, maxDepth, type, expression, digestProvider, dsaLabels,
                new getSecKeyDataOperation()
                {
                    @Override
                    public byte[] getSecKeyData(SExpression keyIn)
                    {
                        BigInteger x = BigIntegers.fromUnsignedByteArray(keyIn.getExpressionWithLabelOrFail("x").getBytes(1));
                        return new DSASecretBCPGKey(x).getEncoded();
                    }
                });
        }
        else if (keyType.equals("elg"))
        {
            pubKey = getPublicKey(fingerPrintCalculator, pubKey, expression, PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, elgBigIntegers, new getPublicKeyOperation()
            {
                public BCPGKey getBasePublicKey(BigInteger[] bigIntegers)
                {
                    return new ElGamalPublicBCPGKey(bigIntegers[0], bigIntegers[1], bigIntegers[2]);
                }

                public void assertPublicKeyMatch(BCPGKey k1, BCPGKey k2)
                    throws PGPException
                {
                    ElGamalPublicBCPGKey key1 = (ElGamalPublicBCPGKey)k1;
                    ElGamalPublicBCPGKey key2 = (ElGamalPublicBCPGKey)k2;
                    if (!key1.getP().equals(key2.getP()) || !key1.getG().equals(key2.getG()) || !key1.getY().equals(key2.getY()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }
            });
            secretKeyPacket = getSecKeyPacket(pubKey, keyProtectionRemoverFactory, maxDepth, type, expression, digestProvider, elgLabels,
                new getSecKeyDataOperation()
                {
                    @Override
                    public byte[] getSecKeyData(SExpression keyIn)
                    {
                        BigInteger x = BigIntegers.fromUnsignedByteArray(keyIn.getExpressionWithLabelOrFail("x").getBytes(1));
                        return new ElGamalSecretBCPGKey(x).getEncoded();
                    }
                });
        }
        else if (keyType.equals("rsa"))
        {
            // TODO: type of RSA key?
            pubKey = getPublicKey(fingerPrintCalculator, pubKey, expression, PublicKeyAlgorithmTags.RSA_GENERAL, rsaBigIntegers, new getPublicKeyOperation()
            {
                public BCPGKey getBasePublicKey(BigInteger[] bigIntegers)
                {
                    return new RSAPublicBCPGKey(bigIntegers[0], bigIntegers[1]);
                }

                public void assertPublicKeyMatch(BCPGKey k1, BCPGKey k2)
                    throws PGPException
                {
                    RSAPublicBCPGKey key1 = (RSAPublicBCPGKey)k1;
                    RSAPublicBCPGKey key2 = (RSAPublicBCPGKey)k2;
                    if (!key1.getModulus().equals(key2.getModulus())
                        || !key1.getPublicExponent().equals(key2.getPublicExponent()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }
            });
            secretKeyPacket = getSecKeyPacket(pubKey, keyProtectionRemoverFactory, maxDepth, type, expression, digestProvider, rsaLabels,
                new getSecKeyDataOperation()
                {
                    @Override
                    public byte[] getSecKeyData(SExpression keyIn)
                    {
                        BigInteger d = BigIntegers.fromUnsignedByteArray(keyIn.getExpressionWithLabelOrFail("d").getBytes(1));
                        BigInteger p = BigIntegers.fromUnsignedByteArray(keyIn.getExpressionWithLabelOrFail("p").getBytes(1));
                        BigInteger q = BigIntegers.fromUnsignedByteArray(keyIn.getExpressionWithLabelOrFail("q").getBytes(1));
                        return new RSASecretBCPGKey(d, p, q).getEncoded();
                    }
                });
        }
        else
        {
            throw new PGPException("unknown key type: " + keyType);
        }
        return new PublicKeyAlgorithmTags[]{secretKeyPacket, pubKey};
    }

    private interface getPublicKeyOperation
    {
        BCPGKey getBasePublicKey(BigInteger[] bigIntegers);

        void assertPublicKeyMatch(BCPGKey key1, BCPGKey key2)
            throws PGPException;
    }

    private static PGPPublicKey getPublicKey(KeyFingerPrintCalculator fingerPrintCalculator, PGPPublicKey pubKey, SExpression expression,
                                             int publicKeyAlgorithmTags, String[] bigIntegerLabels, getPublicKeyOperation operation)
        throws PGPException
    {
        int flag = 0, flag_break = (1 << bigIntegerLabels.length) - 1;
        BigInteger[] bigIntegers = new BigInteger[bigIntegerLabels.length];
        for (Iterator it = expression.getValues().iterator(); it.hasNext();)
        {
            Object item = it.next();
            if (item instanceof SExpression)
            {
                SExpression exp = (SExpression)item;
                String str = exp.getString(0);
                for (int i = 0; i < bigIntegerLabels.length; ++i)
                {
                    if ((flag & (1 << i)) == 0 && str.equals(bigIntegerLabels[i]))
                    {
                        bigIntegers[i] = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                        flag |= 1 << i;
                        if (flag == flag_break)
                        {
                            break;
                        }
                    }
                }
            }
        }
        if (flag != flag_break)
        {
            throw new IllegalArgumentException("The public key should not be null");
        }
        BCPGKey basePubKey = operation.getBasePublicKey(bigIntegers);
        if (pubKey != null)
        {
            operation.assertPublicKeyMatch(basePubKey, pubKey.getPublicKeyPacket().getKey());
        }
        else
        {
            pubKey = new PGPPublicKey(new PublicKeyPacket(publicKeyAlgorithmTags, new Date(), basePubKey), fingerPrintCalculator);
        }
        return pubKey;
    }

    private interface getSecKeyDataOperation
    {
        byte[] getSecKeyData(SExpression keyIn);
    }

    private static SecretKeyPacket getSecKeyPacket(PGPPublicKey pubKey, PBEProtectionRemoverFactory keyProtectionRemoverFactory, int maxDepth, int type,
                                                   SExpression expression, PGPDigestCalculatorProvider digestProvider,
                                                   Map<Integer, String[]> labels, getSecKeyDataOperation operation)
        throws PGPException, IOException
    {
        byte[] secKeyData = null;
        S2K s2K = null;
        byte[] nonce = null;
        SExpression keyIn;
        if (type != ProtectionFormatTypeTags.SHADOWED_PRIVATE_KEY)
        {
            if (type == ProtectionFormatTypeTags.PROTECTED_PRIVATE_KEY)
            {
                SExpression protectedKey = expression.getExpressionWithLabel("protected");
                if (protectedKey == null)
                {
                    throw new IllegalArgumentException(type + " does not have protected block");
                }
                String protectionStr = protectedKey.getString(1);
                int protection = getProtectionMode(protectionStr);
                if (protection == ProtectionModeTags.OPENPGP_S2K3_OCB_AES || protection == ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC)
                {
                    byte[] data;
                    SExpression protectionKeyParameters = protectedKey.getExpression(2);
                    SExpression s2kParams = protectionKeyParameters.getExpression(0);
                    // TODO select correct hash
                    s2K = new S2K(PGPUtil.getDigestIDForName(s2kParams.getString(0)), s2kParams.getBytes(1), s2kParams.getInt(2));
                    nonce = protectionKeyParameters.getBytes(1);
                    PBESecretKeyDecryptor keyDecryptor = keyProtectionRemoverFactory.createDecryptor(protectionStr);
                    byte[] key = keyDecryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_128, s2K);
                    byte[] keyData = protectedKey.getBytes(3);
                    if (protection == ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC)
                    {
                        data = keyDecryptor.recoverKeyData(SymmetricKeyAlgorithmTags.AES_128, key, nonce, keyData, 0, keyData.length);
                        keyIn = SExpression.parseCanonical(new ByteArrayInputStream(data), maxDepth);
                        if (digestProvider != null)
                        {
                            PGPDigestCalculator digestCalculator = digestProvider.get(HashAlgorithmTags.SHA1);
                            OutputStream dOut = digestCalculator.getOutputStream();
                            byte[] aad = SExpression.buildExpression(expression, keyIn.getExpression(0), (String[])labels.get(Integers.valueOf(protection))).toCanonicalForm();
                            dOut.write(aad);
                            byte[] check = digestCalculator.getDigest();
                            byte[] hashBytes = keyIn.getExpression(1).getBytes(2);
                            if (!Arrays.constantTimeAreEqual(check, hashBytes))
                            {
                                throw new PGPException("checksum on protected data failed in SExpr");
                            }
                        }
                        keyIn = keyIn.getExpression(0);
                    }
                    else //ProtectionModeTags.OPENPGP_S2K3_OCB_AES
                    {
                        String[] filter = (String[])labels.get(Integers.valueOf(protection));
                        if (filter == null)
                        {
                            // TODO could not get client to generate protected elgamal keys
                            throw new IllegalStateException("no decryption support for protected elgamal keys");
                        }
                        byte[] aad = SExpression.buildExpression(expression, filter).toCanonicalForm();
                        data = ((PGPSecretKeyDecryptorWithAAD)keyDecryptor).recoverKeyData(SymmetricKeyAlgorithmTags.AES_128, key,
                            nonce, aad, keyData, 0, keyData.length);
                        keyIn = SExpression.parseCanonical(new ByteArrayInputStream(data), maxDepth).getExpression(0);
                    }
                }
                else
                {
                    // openpgp-native is not supported for now
                    throw new PGPException("unsupported protection type " + protectedKey.getString(1));
                }
            }
            else
            {
                keyIn = expression;
            }
            secKeyData = operation.getSecKeyData(keyIn);
        }
        return new SecretKeyPacket(pubKey.getPublicKeyPacket(), SymmetricKeyAlgorithmTags.NULL, s2K, nonce, secKeyData);
    }

    private static BCPGKey getECCBasePublicKey(SExpression expression)
    {
        byte[] qoint = null;
        String curve = null;
        int flag = 0;
        for (Iterator it = expression.getValues().iterator(); it.hasNext();)
        {
            Object item = it.next();
            if (item instanceof SExpression)
            {
                SExpression exp = (SExpression)item;
                String label = exp.getString(0);
                if (label.equals("curve"))
                {
                    curve = exp.getString(1);
                    flag |= 1;
                }
                else if (label.equals("q"))
                {
                    qoint = exp.getBytes(1);
                    flag |= 2;
                }
                if (flag == 3)
                {
                    break;
                }
            }
        }
        if (flag != 3)
        {
            throw new IllegalArgumentException("no curve expression");
        }
        else if (curve.startsWith("NIST"))
        {
            curve = curve.substring("NIST".length()).trim();
        }
        String curve_lowercase = Strings.toLowerCase(curve);
        if (curve_lowercase.equals("ed25519"))
        {
            return new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed25519, new BigInteger(1, qoint));
        }
        else if (curve_lowercase.equals("ed448"))
        {
            return new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, qoint));
        }
        else
        {
            ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(curve);
            X9ECParametersHolder holder = CustomNamedCurves.getByNameLazy(curve);
            if (holder == null && oid != null)
            {
                holder = TeleTrusTNamedCurves.getByOIDLazy(oid);
            }
            if (holder == null)
            {
                throw new IllegalStateException("unable to resolve parameters for " + curve);
            }
            ECPoint pnt = holder.getCurve().decodePoint(qoint);
            return new ECDSAPublicBCPGKey(oid, pnt);
        }
    }

    private static void assertEccPublicKeyMath(BCPGKey key1, PGPPublicKey key2)
        throws PGPException
    {
        if (key1 instanceof ECDSAPublicBCPGKey)
        {
            ECPublicBCPGKey assocPubKey = (ECPublicBCPGKey)key2.getPublicKeyPacket().getKey();
            if (!((ECDSAPublicBCPGKey)key1).getCurveOID().equals(assocPubKey.getCurveOID())
                || !((ECDSAPublicBCPGKey)key1).getEncodedPoint().equals(assocPubKey.getEncodedPoint()))
            {
                throw new PGPException("passed in public key does not match secret key");
            }
        }
        else if (key1 instanceof EdDSAPublicBCPGKey)
        {
            EdDSAPublicBCPGKey assocPubKey = (EdDSAPublicBCPGKey)key2.getPublicKeyPacket().getKey();
            if (!((EdDSAPublicBCPGKey)key1).getCurveOID().equals(assocPubKey.getCurveOID())
                || !((EdDSAPublicBCPGKey)key1).getEncodedPoint().equals(assocPubKey.getEncodedPoint()))
            {
                throw new PGPException("passed in public key does not match secret key");
            }
        }
        else
        {
            throw new PGPException("unknown key type: " + (key1 != null ? key1.getClass().getName() : "null"));
        }
    }

    public static int getProtectionType(String str)
    {
        if (str.equals("private-key"))
        {
            return ProtectionFormatTypeTags.PRIVATE_KEY;
        }
        else if (str.equals("protected-private-key"))
        {
            return ProtectionFormatTypeTags.PROTECTED_PRIVATE_KEY;
        }
        else if (str.equals("shadowed-private-key"))
        {
            return ProtectionFormatTypeTags.SHADOWED_PRIVATE_KEY;
        }
        // The other two types are not supported for now
        return -1;
    }

    private static int getProtectionMode(String str)
    {
        if (str.equals("openpgp-s2k3-sha1-aes-cbc"))
        {
            return ProtectionModeTags.OPENPGP_S2K3_SHA1_AES_CBC;
        }
        else if (str.equals("openpgp-s2k3-ocb-aes"))
        {
            return ProtectionModeTags.OPENPGP_S2K3_OCB_AES;
        }
        // The other mode is not supported for now
        return -1;
    }
}