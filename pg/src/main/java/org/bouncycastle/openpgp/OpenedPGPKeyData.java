package org.bouncycastle.openpgp;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.gpg.SExpression;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * Wraps PGP key headers and pgp key SExpression
 */
public class OpenedPGPKeyData
{
    private final List<PGPExtendedKeyHeader> headerList;
    private final SExpression keyExpression;

    public OpenedPGPKeyData(List<PGPExtendedKeyHeader> headerList, SExpression keyExpression)
    {
        this.headerList = Collections.unmodifiableList(headerList);
        this.keyExpression = keyExpression;
    }

    public List<PGPExtendedKeyHeader> getHeaderList()
    {
        return headerList;
    }

    public SExpression getKeyExpression()
    {
        return keyExpression;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public String getKeyType()
    {
        return null;
    }

    public ExtendedPGPSecretKey getKeyData(PGPPublicKey publicKey, PGPDigestCalculatorProvider digestCalculatorProvider,
                                           PBEProtectionRemoverFactory keyProtectionRemoverFactory,
                                           KeyFingerPrintCalculator fingerPrintCalculator, int maxDepth)
        throws PGPException, IOException

    {
        String type = keyExpression.getString(0);
        ArrayList<PGPExtendedKeyAttribute> attributeList = new ArrayList<PGPExtendedKeyAttribute>();

        if (type.equals("shadowed-private-key") || type.equals("protected-private-key") || type.equals("private-key"))
        {
            SExpression keyExpression = getKeyExpression().getExpression(1);


            if (keyExpression.hasLabel("ecc"))
            {
                PGPPublicKey pgpPublicKeyFound = getECCPublicKey(keyExpression, fingerPrintCalculator);
                if (publicKey != null && pgpPublicKeyFound != null)
                {
                    ECPublicBCPGKey basePubKey = (ECPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
                    ECPublicBCPGKey assocPubKey = (ECPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
                    if (!basePubKey.getCurveOID().equals(assocPubKey.getCurveOID())
                        || !basePubKey.getEncodedPoint().equals(assocPubKey.getEncodedPoint()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }

                publicKey = pgpPublicKeyFound;

                UnwrapResult unwrapResult;

                if (type.equals("shadowed-private-key"))
                {
                    unwrapResult = null;
                }
                else if (type.equals("protected-private-key"))
                {
                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
                    if (protectedKey == null)
                    {
                        throw new IllegalArgumentException(type + " does not have protected block");
                    }

                    String protectionType = protectedKey.getString(1);

                    if (protectionType.indexOf("aes") >= 0)
                    {
                        unwrapResult = unwrapECCSecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey, keyProtectionRemoverFactory);
                    }
                    else
                    {
                        throw new PGPException("unsupported protection type");
                    }
                }
                else
                {
                    String curve;
                    SExpression curveExpr = keyExpression.getExpressionWithLabel("curve");
                    if (curveExpr != null)
                    {
                        curve = curveExpr.getString(1);
                    }
                    else
                    {
                        throw new IllegalStateException("no curve expression");
                    }

                    unwrapResult = new UnwrapResult(keyExpression, null, null, curve);
                }

                BigInteger d = new BigInteger(1, unwrapResult.expression.getExpressionWithLabelOrFail("d").getBytes(1));


                if (unwrapResult.metaData == null)
                {
                    throw new IllegalStateException("expecting unwrap result to have meta data defining the curve");
                }

                String curve = unwrapResult.metaData.toString();
                BCPGKey key;
                if (curve.startsWith("NIST") || curve.startsWith("brain"))
                {
                    key = new ECSecretBCPGKey(d);
                }
                else
                {
                    key = new EdSecretBCPGKey(d);
                }

                return new ExtendedPGPSecretKey(
                    headerList,
                    attributeList,
                    new SecretKeyPacket(
                        publicKey.getPublicKeyPacket(),
                        SymmetricKeyAlgorithmTags.NULL,
                        unwrapResult.s2K,
                        unwrapResult.iv,
                        key.getEncoded()),
                    publicKey);

            }
            else if (keyExpression.hasLabel("elg"))
            {
                PGPPublicKey pgpPublicKeyFound = getDSAPublicKey(keyExpression, fingerPrintCalculator);
                if (publicKey != null && pgpPublicKeyFound != null)
                {

                    ElGamalPublicBCPGKey basePubKey = (ElGamalPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
                    ElGamalPublicBCPGKey assocPubKey = (ElGamalPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
                    if (!basePubKey.getP().equals(assocPubKey.getP())
                        || !basePubKey.getG().equals(assocPubKey.getG())
                        || !basePubKey.getY().equals(assocPubKey.getY()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }
                publicKey = pgpPublicKeyFound;

                UnwrapResult unwrapResult;

                if (type.equals("shadowed-private-key"))
                {
                    unwrapResult = null;
                }
                else if (type.equals("protected-private-key"))
                {
                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
                    if (protectedKey == null)
                    {
                        throw new IllegalArgumentException(type + " does not have protected block");
                    }

                    String protectionType = protectedKey.getString(1);


                    if (protectionType.indexOf("aes") >= 0)
                    {
                        // TODO could not get client to generate protected elgamal keys
                        throw new IllegalStateException("no decryption support for protected elgamal keys");
                        // unwrapResult = unwrapDSASecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey);
                    }
                    else
                    {
                        throw new PGPException("unsupported protection type");
                    }
                }
                else
                {
                    unwrapResult = new UnwrapResult(keyExpression, null, null);
                }

                BigInteger x = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("x").getBytes(1));

                if (keyExpression.hasLabel("elg"))
                {
                    return new ExtendedPGPSecretKey(
                        headerList,
                        attributeList,
                        new SecretKeyPacket(
                            publicKey.getPublicKeyPacket(),
                            SymmetricKeyAlgorithmTags.NULL,
                            unwrapResult.s2K,
                            unwrapResult.iv,
                            new ElGamalSecretBCPGKey(x).getEncoded()),
                        publicKey);
                }
                else
                {

                    return new ExtendedPGPSecretKey(
                        headerList,
                        attributeList,
                        new SecretKeyPacket(
                            publicKey.getPublicKeyPacket(),
                            SymmetricKeyAlgorithmTags.NULL,
                            unwrapResult.s2K,
                            unwrapResult.iv,
                            new DSASecretBCPGKey(x).getEncoded()),
                        publicKey);
                }

            }
            else if (keyExpression.hasLabel("dsa"))
            {
                PGPPublicKey pgpPublicKeyFound = getDSAPublicKey(keyExpression, fingerPrintCalculator);
                if (publicKey != null && pgpPublicKeyFound != null)
                {
                    DSAPublicBCPGKey basePubKey = (DSAPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
                    DSAPublicBCPGKey assocPubKey = (DSAPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
                    if (!basePubKey.getP().equals(assocPubKey.getP())
                        || !basePubKey.getQ().equals(assocPubKey.getQ())
                        || !basePubKey.getG().equals(assocPubKey.getG())
                        || !basePubKey.getY().equals(assocPubKey.getY()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }
                publicKey = pgpPublicKeyFound;

                UnwrapResult unwrapResult;

                if (type.equals("shadowed-private-key"))
                {
                    unwrapResult = null;
                }
                else if (type.equals("protected-private-key"))
                {
                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
                    if (protectedKey == null)
                    {
                        throw new IllegalArgumentException(type + " does not have protected block");
                    }

                    String protectionType = protectedKey.getString(1);


                    if (protectionType.indexOf("aes") >= 0)
                    {
                        unwrapResult = unwrapDSASecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey, keyProtectionRemoverFactory);
                    }
                    else
                    {
                        throw new PGPException("unsupported protection type");
                    }
                }
                else
                {
                    unwrapResult = new UnwrapResult(keyExpression, null, null);
                }

                BigInteger x = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("x").getBytes(1));

                return new ExtendedPGPSecretKey(
                    headerList,
                    attributeList,
                    new SecretKeyPacket(
                        publicKey.getPublicKeyPacket(),
                        SymmetricKeyAlgorithmTags.NULL,
                        unwrapResult.s2K,
                        unwrapResult.iv,
                        new DSASecretBCPGKey(x).getEncoded()),
                    publicKey);


            }
            else if (keyExpression.hasLabel("rsa"))
            {
                PGPPublicKey pgpPublicKeyFound = getRSAPublicKey(keyExpression, fingerPrintCalculator);

                // Test passed in PublicKey matches the found public key
                if (publicKey != null && pgpPublicKeyFound != null)
                {
                    RSAPublicBCPGKey basePubKey = (RSAPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
                    RSAPublicBCPGKey assocPubKey = (RSAPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
                    if (!basePubKey.getModulus().equals(assocPubKey.getModulus())
                        || !basePubKey.getPublicExponent().equals(assocPubKey.getPublicExponent()))
                    {
                        throw new PGPException("passed in public key does not match secret key");
                    }
                }
                publicKey = pgpPublicKeyFound;

                UnwrapResult unwrapResult;

                if (type.equals("shadowed-private-key"))
                {
                    unwrapResult = null;
                }
                else if (type.equals("protected-private-key"))
                {
                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
                    if (protectedKey == null)
                    {
                        throw new IllegalArgumentException(type + " does not have protected block");
                    }

                    String protectionType = protectedKey.getString(1);


                    if (protectionType.indexOf("aes") >= 0)
                    {
                        unwrapResult = unwrapRSASecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey, keyProtectionRemoverFactory);
                    }
                    else
                    {
                        throw new PGPException("unsupported protection type");
                    }
                }
                else
                {
                    unwrapResult = new UnwrapResult(keyExpression, null, null);
                }


                for (Iterator it = keyExpression.filterOut(new String[] { "rsa", "e", "n", "d", "p", "q", "u", "protected" }).getValues().iterator(); it.hasNext();)
                {
                    Object o = it.next();
                    if (o instanceof SExpression)
                    {
                        attributeList.add(((SExpression)o).toAttribute());
                    }
                    else
                    {
                        attributeList.add(PGPExtendedKeyAttribute.builder().addAttribute(o).build());
                    }
                }

                if (unwrapResult == null)
                {
                    return new ExtendedPGPSecretKey(
                        headerList,
                        attributeList,
                        null,
                        publicKey);
                }

                BigInteger d = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("d").getBytes(1));
                BigInteger p = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("p").getBytes(1));
                BigInteger q = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("q").getBytes(1));

                return new ExtendedPGPSecretKey(
                    headerList,
                    attributeList,
                    new SecretKeyPacket(
                        publicKey.getPublicKeyPacket(),
                        SymmetricKeyAlgorithmTags.NULL,
                        unwrapResult.s2K,
                        unwrapResult.iv,
                        new RSASecretBCPGKey(d, p, q).getEncoded()),
                    publicKey);

            }
        }

        return null;
    }


//    private ExtendedPGPSecretKey fromSExpression(ArrayList<PGPExtendedKeyHeader> preamble, SExpression expression, PGPPublicKey publicKey, int maxDepth,  PBEProtectionRemoverFactory keyProtectionRemoverFactory)
//        throws PGPException, IOException
//    {
//        String type = expression.getString(0);
//        ArrayList<PGPExtendedKeyAttribute> attributeList = new ArrayList<PGPExtendedKeyAttribute>();
//
//        if (type.equals("shadowed-private-key") || type.equals("protected-private-key") || type.equals("private-key"))
//        {
//            SExpression keyExpression = expression.getExpression(1);
//
//
//            if (keyExpression.hasLabel("ecc"))
//            {
//                PGPPublicKey pgpPublicKeyFound = getECCPublicKey(keyExpression,);
//                if (publicKey != null && pgpPublicKeyFound != null)
//                {
//                    ECPublicBCPGKey basePubKey = (ECPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
//                    ECPublicBCPGKey assocPubKey = (ECPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
//                    if (!basePubKey.getCurveOID().equals(assocPubKey.getCurveOID())
//                        || !basePubKey.getEncodedPoint().equals(assocPubKey.getEncodedPoint()))
//                    {
//                        throw new PGPException("passed in public key does not match secret key");
//                    }
//                }
//
//                publicKey = pgpPublicKeyFound;
//
//                UnwrapResult unwrapResult;
//
//                if (type.equals("shadowed-private-key"))
//                {
//                    unwrapResult = null;
//                }
//                else if (type.equals("protected-private-key"))
//                {
//                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
//                    if (protectedKey == null)
//                    {
//                        throw new IllegalArgumentException(type + " does not have protected block");
//                    }
//
//                    String protectionType = protectedKey.getString(1);
//
//                    if (protectionType.indexOf("aes") >= 0)
//                    {
//                        unwrapResult = unwrapECCSecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey,keyProtectionRemoverFactory);
//                    }
//                    else
//                    {
//                        throw new PGPException("unsupported protection type");
//                    }
//                }
//                else
//                {
//                    String curve;
//                    SExpression curveExpr = keyExpression.getExpressionWithLabel("curve");
//                    if (curveExpr != null)
//                    {
//                        curve = curveExpr.getString(1);
//                    }
//                    else
//                    {
//                        throw new IllegalStateException("no curve expression");
//                    }
//
//                    unwrapResult = new UnwrapResult(keyExpression, null, null, curve);
//                }
//
//                BigInteger d = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("d").getBytes(1));
//
//
//                if (unwrapResult.metaData == null)
//                {
//                    throw new IllegalStateException("expecting unwrap result to have meta data defining the curve");
//                }
//
//                String curve = unwrapResult.metaData.toString();
//                BCPGKey key;
//                if (curve.startsWith("NIST") || curve.startsWith("brain"))
//                {
//                    key = new ECSecretBCPGKey(d);
//                }
//                else
//                {
//                    key = new EdSecretBCPGKey(d);
//                }
//
//                return new ExtendedPGPSecretKey(
//                    preamble,
//                    attributeList,
//                    new SecretKeyPacket(
//                        publicKey.getPublicKeyPacket(),
//                        SymmetricKeyAlgorithmTags.NULL,
//                        unwrapResult.s2K,
//                        unwrapResult.iv,
//                        key.getEncoded()),
//                    publicKey);
//
//            }
//            else if (keyExpression.hasLabel("elg"))
//            {
//                PGPPublicKey pgpPublicKeyFound = getDSAPublicKey(keyExpression);
//                if (publicKey != null && pgpPublicKeyFound != null)
//                {
//
//                    ElGamalPublicBCPGKey basePubKey = (ElGamalPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
//                    ElGamalPublicBCPGKey assocPubKey = (ElGamalPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
//                    if (!basePubKey.getP().equals(assocPubKey.getP())
//                        || !basePubKey.getG().equals(assocPubKey.getG())
//                        || !basePubKey.getY().equals(assocPubKey.getY()))
//                    {
//                        throw new PGPException("passed in public key does not match secret key");
//                    }
//                }
//                publicKey = pgpPublicKeyFound;
//
//                UnwrapResult unwrapResult;
//
//                if (type.equals("shadowed-private-key"))
//                {
//                    unwrapResult = null;
//                }
//                else if (type.equals("protected-private-key"))
//                {
//                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
//                    if (protectedKey == null)
//                    {
//                        throw new IllegalArgumentException(type + " does not have protected block");
//                    }
//
//                    String protectionType = protectedKey.getString(1);
//
//
//                    if (protectionType.indexOf("aes") >= 0)
//                    {
//                        // TODO could not get client to generate protected elgamal keys
//                        throw new IllegalStateException("no decryption support for protected elgamal keys");
//                        // unwrapResult = unwrapDSASecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey);
//                    }
//                    else
//                    {
//                        throw new PGPException("unsupported protection type");
//                    }
//                }
//                else
//                {
//                    unwrapResult = new UnwrapResult(keyExpression, null, null);
//                }
//
//                BigInteger x = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("x").getBytes(1));
//
//                if (keyExpression.hasLabel("elg"))
//                {
//                    return new ExtendedPGPSecretKey(
//                        preamble,
//                        attributeList,
//                        new SecretKeyPacket(
//                            publicKey.getPublicKeyPacket(),
//                            SymmetricKeyAlgorithmTags.NULL,
//                            unwrapResult.s2K,
//                            unwrapResult.iv,
//                            new ElGamalSecretBCPGKey(x).getEncoded()),
//                        publicKey);
//                }
//                else
//                {
//
//                    return new ExtendedPGPSecretKey(
//                        preamble,
//                        attributeList,
//                        new SecretKeyPacket(
//                            publicKey.getPublicKeyPacket(),
//                            SymmetricKeyAlgorithmTags.NULL,
//                            unwrapResult.s2K,
//                            unwrapResult.iv,
//                            new DSASecretBCPGKey(x).getEncoded()),
//                        publicKey);
//                }
//
//            }
//            else if (keyExpression.hasLabel("dsa"))
//            {
//                PGPPublicKey pgpPublicKeyFound = getDSAPublicKey(keyExpression);
//                if (publicKey != null && pgpPublicKeyFound != null)
//                {
//                    DSAPublicBCPGKey basePubKey = (DSAPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
//                    DSAPublicBCPGKey assocPubKey = (DSAPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
//                    if (!basePubKey.getP().equals(assocPubKey.getP())
//                        || !basePubKey.getQ().equals(assocPubKey.getQ())
//                        || !basePubKey.getG().equals(assocPubKey.getG())
//                        || !basePubKey.getY().equals(assocPubKey.getY()))
//                    {
//                        throw new PGPException("passed in public key does not match secret key");
//                    }
//                }
//                publicKey = pgpPublicKeyFound;
//
//                UnwrapResult unwrapResult;
//
//                if (type.equals("shadowed-private-key"))
//                {
//                    unwrapResult = null;
//                }
//                else if (type.equals("protected-private-key"))
//                {
//                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
//                    if (protectedKey == null)
//                    {
//                        throw new IllegalArgumentException(type + " does not have protected block");
//                    }
//
//                    String protectionType = protectedKey.getString(1);
//
//
//                    if (protectionType.indexOf("aes") >= 0)
//                    {
//                        unwrapResult = unwrapDSASecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey);
//                    }
//                    else
//                    {
//                        throw new PGPException("unsupported protection type");
//                    }
//                }
//                else
//                {
//                    unwrapResult = new UnwrapResult(keyExpression, null, null);
//                }
//
//                BigInteger x = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("x").getBytes(1));
//
//                return new ExtendedPGPSecretKey(
//                    preamble,
//                    attributeList,
//                    new SecretKeyPacket(
//                        publicKey.getPublicKeyPacket(),
//                        SymmetricKeyAlgorithmTags.NULL,
//                        unwrapResult.s2K,
//                        unwrapResult.iv,
//                        new DSASecretBCPGKey(x).getEncoded()),
//                    publicKey);
//
//
//            }
//            else if (keyExpression.hasLabel("rsa"))
//            {
//                PGPPublicKey pgpPublicKeyFound = getRSAPublicKey(keyExpression);
//
//                // Test passed in PublicKey matches the found public key
//                if (publicKey != null && pgpPublicKeyFound != null)
//                {
//                    RSAPublicBCPGKey basePubKey = (RSAPublicBCPGKey)publicKey.getPublicKeyPacket().getKey();
//                    RSAPublicBCPGKey assocPubKey = (RSAPublicBCPGKey)pgpPublicKeyFound.getPublicKeyPacket().getKey();
//                    if (!basePubKey.getModulus().equals(assocPubKey.getModulus())
//                        || !basePubKey.getPublicExponent().equals(assocPubKey.getPublicExponent()))
//                    {
//                        throw new PGPException("passed in public key does not match secret key");
//                    }
//                }
//                publicKey = pgpPublicKeyFound;
//
//                UnwrapResult unwrapResult;
//
//                if (type.equals("shadowed-private-key"))
//                {
//                    unwrapResult = null;
//                }
//                else if (type.equals("protected-private-key"))
//                {
//                    SExpression protectedKey = keyExpression.getExpressionWithLabel("protected");
//                    if (protectedKey == null)
//                    {
//                        throw new IllegalArgumentException(type + " does not have protected block");
//                    }
//
//                    String protectionType = protectedKey.getString(1);
//
//
//                    if (protectionType.indexOf("aes") >= 0)
//                    {
//                        unwrapResult = unwrapRSASecretKey(protectionType, publicKey, maxDepth, keyExpression, protectedKey);
//                    }
//                    else
//                    {
//                        throw new PGPException("unsupported protection type");
//                    }
//                }
//                else
//                {
//                    unwrapResult = new UnwrapResult(keyExpression, null, null);
//                }
//
//
//                for (Object o : keyExpression.filterOut("rsa", "e", "n", "d", "p", "q", "u", "protected").getValues())
//                {
//                    if (o instanceof SExpression)
//                    {
//                        attributeList.add(((SExpression)o).toAttribute());
//                    }
//                    else
//                    {
//                        attributeList.add(PGPExtendedKeyAttribute.builder().addAttribute(o).build());
//                    }
//                }
//
//                if (unwrapResult == null)
//                {
//                    return new ExtendedPGPSecretKey(
//                        preamble,
//                        attributeList,
//                        null,
//                        publicKey);
//                }
//
//                BigInteger d = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("d").getBytes(1));
//                BigInteger p = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("p").getBytes(1));
//                BigInteger q = BigIntegers.fromUnsignedByteArray(unwrapResult.expression.getExpressionWithLabelOrFail("q").getBytes(1));
//
//                return new ExtendedPGPSecretKey(
//                    preamble,
//                    attributeList,
//                    new SecretKeyPacket(
//                        publicKey.getPublicKeyPacket(),
//                        SymmetricKeyAlgorithmTags.NULL,
//                        unwrapResult.s2K,
//                        unwrapResult.iv,
//                        new RSASecretBCPGKey(d, p, q).getEncoded()),
//                    publicKey);
//
//            }
//        }
//
//        return null;
//    }

    private UnwrapResult unwrapDSASecretKey(
        String protectionType, PGPPublicKey publicKey, int maxDepth, SExpression keyExpression, SExpression protectedKey,
        PBEProtectionRemoverFactory keyProtectionRemoverFactory
    )
        throws PGPException, IOException
    {

        if (protectionType.equals("openpgp-s2k3-sha1-aes-cbc"))
        {
            // TODO could not get client to generate this.
            throw new IllegalArgumentException("openpgp-s2k3-sha1-aes-cbc not supported on newer key type");
        }
        else if (protectionType.equals("openpgp-s2k3-ocb-aes"))
        {
            //
            // Create AAD.
            //
            SExpression.Builder builder = SExpression.builder().addValue("dsa");
            addPublicKey(publicKey, builder);
            builder.addContent(keyExpression.filterOut(new String[] { "dsa", "p", "q", "g", "y", "protected" }));
            byte[] aad = builder.build().toCanonicalForm();


            SExpression protectionKeyParameters = protectedKey.getExpression(2);
            SExpression s2kParams = protectionKeyParameters.getExpression(0);
            // TODO select correct hash
            S2K s2K = new S2K(PGPUtil.getDigestIDForName(s2kParams.getString(0)), s2kParams.getBytes(1), s2kParams.getInt(2));


            byte[] nonce = protectionKeyParameters.getBytes(1);

            PBESecretKeyDecryptor decryptor = keyProtectionRemoverFactory.createDecryptor("ocb");
            byte[] key = decryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_128, s2K);

            byte[] keyData = protectedKey.getBytes(3);


            return new UnwrapResult(SExpression.parse(
                ((PGPSecretKeyDecryptorWithAAD)decryptor).recoverKeyData(
                    SymmetricKeyAlgorithmTags.AES_128,
                    key, nonce, aad, keyData, 0, keyData.length),
                maxDepth).getExpression(0), s2K, Arrays.clone(nonce));

        }

        throw new PGPException("unhandled protection type " + protectionType);
    }

    private UnwrapResult unwrapECCSecretKey(
        String protectionType,
        PGPPublicKey publicKey,
        int maxDepth,
        SExpression keyExpression,
        SExpression protectedKey,
        PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws PGPException, IOException
    {

        if (protectionType.equals("openpgp-s2k3-sha1-aes-cbc"))
        {
            // TODO could not get client to generate this.
            throw new IllegalArgumentException("openpgp-s2k3-sha1-aes-cbc not supported on newer key type");
        }
        else if (protectionType.equals("openpgp-s2k3-ocb-aes"))
        {

            SExpression.Builder builder = SExpression.builder().addValue("ecc");
            builder.addContent(keyExpression.filterIn(new String[] { "curve", "flags" }));
            addPublicKey(publicKey, builder);
            builder.addContent(keyExpression.filterOut(new String[] { "ecc", "flags", "curve", "q", "protected" }));
            byte[] aad = builder.build().toCanonicalForm();

            String curve;
            SExpression curveExpr = keyExpression.getExpressionWithLabel("curve");
            if (curveExpr != null)
            {
                curve = curveExpr.getString(1);
            }
            else
            {
                throw new IllegalStateException("no curve expression");
            }

            SExpression protectionKeyParameters = protectedKey.getExpression(2);
            SExpression s2kParams = protectionKeyParameters.getExpression(0);
            // TODO select correct hash
            S2K s2K = new S2K(PGPUtil.getDigestIDForName(s2kParams.getString(0)), s2kParams.getBytes(1), s2kParams.getInt(2));

            // OCB Nonce
            byte[] nonce = protectionKeyParameters.getBytes(1);

            PBESecretKeyDecryptor decryptor = keyProtectionRemoverFactory.createDecryptor("ocb");
            byte[] key = decryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_128, s2K);

            byte[] keyData = protectedKey.getBytes(3);


            return new UnwrapResult(SExpression.parse(
                ((PGPSecretKeyDecryptorWithAAD)decryptor).recoverKeyData(
                    SymmetricKeyAlgorithmTags.AES_128,
                    key, nonce, aad, keyData, 0, keyData.length),
                maxDepth).getExpression(0), s2K, Arrays.clone(nonce), curve);

        }

        throw new PGPException("unhandled protection type " + protectionType);
    }

    private PGPPublicKey getECCPublicKey(SExpression expression, KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        byte[] qoint = null;
        String curve = null;

        for (Iterator it = expression.getValues().iterator(); it.hasNext();)
        {
            Object item = it.next();
            if (item instanceof SExpression)
            {
                SExpression exp = (SExpression)item;
                if (exp.hasLabel("curve"))
                {
                    curve = exp.getString(1);
                }
                else if (exp.hasLabel("q"))
                {
                    qoint = exp.getBytes(1);
                }
            }
        }

        if (curve == null || qoint == null)
        {
            return null;
        }

        if (curve.startsWith("Curve"))
        {
            curve = Strings.toLowerCase(curve);
        }
        else if (curve.startsWith("NIST"))
        {
            curve = curve.substring("NIST".length()).trim();
        }

        PublicKeyPacket publicKeyPacket;
        if (Strings.toLowerCase(curve).equals("ed25519"))
        {
            EdDSAPublicBCPGKey basePubKey = new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed25519, new BigInteger(1, qoint));
            publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.EDDSA_LEGACY, new Date(), basePubKey);
        }
        else if (Strings.toLowerCase(curve).equals("ed448"))
        {
            EdDSAPublicBCPGKey basePubKey = new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, qoint));
            publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.EDDSA_LEGACY, new Date(), basePubKey);
        }
        else
        {
            ASN1ObjectIdentifier oid = ECNamedCurveTable.getOID(curve);
            X9ECParametersHolder holder = CustomNamedCurves.getByNameLazy(curve);
            if (holder == null)
            {
                holder = TeleTrusTNamedCurves.getByOIDLazy(oid);
            }

            if (holder == null)
            {
                throw new IllegalStateException("unable to resolve parameters for " + curve);
            }

            ECPoint pnt = holder.getCurve().decodePoint(qoint);
            ECPublicBCPGKey basePubKey = new ECDSAPublicBCPGKey(oid, pnt);
            publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.ECDSA, new Date(), basePubKey);
        }

        return new PGPPublicKey(publicKeyPacket, fingerPrintCalculator);
    }

    private PGPPublicKey getDSAPublicKey(SExpression expression, KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        BigInteger p = null;
        BigInteger q = null;
        BigInteger g = null;
        BigInteger y = null;

        for (Iterator it = expression.getValues().iterator(); it.hasNext();)
        {
            Object item = it.next();
            if (item instanceof SExpression)
            {
                SExpression exp = (SExpression)item;
                if (exp.hasLabel("p"))
                {
                    p = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                }
                else if (exp.hasLabel("q"))
                {
                    q = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                }
                else if (exp.hasLabel("g"))
                {
                    g = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                }
                else if (exp.hasLabel("y"))
                {
                    y = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                }
            }
        }

        if (p == null || (!expression.hasLabel("elg") && q == null) || g == null || y == null)
        {
            return null;
        }

        PublicKeyPacket publicKeyPacket;
        if (expression.hasLabel("elg"))
        {
            // TODO how to tell if Elgamal General or Encrypt?
            publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, new Date(), new ElGamalPublicBCPGKey(p, g, y));
        }
        else
        {
            publicKeyPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.DSA, new Date(), new DSAPublicBCPGKey(p, q, g, y));
        }

        return new PGPPublicKey(publicKeyPacket, fingerPrintCalculator);
    }

    private UnwrapResult unwrapRSASecretKey(
        String protectionType,
        PGPPublicKey publicKey,
        int maxDepth,
        SExpression keyExpression,
        SExpression protectedKey,
        PBEProtectionRemoverFactory keyProtectionRemoverFactory)
        throws PGPException, IOException
    {

        if (protectionType.equals("openpgp-s2k3-sha1-aes-cbc"))
        {
            // TODO could not get client to generate this.
            throw new IllegalArgumentException("openpgp-s2k3-sha1-aes-cbc not supported on newer key type");
        }
        else if (protectionType.equals("openpgp-s2k3-ocb-aes"))
        {


            SExpression.Builder builder = SExpression.builder().addValue("rsa");
            addPublicKey(publicKey, builder);
            builder.addContent(keyExpression.filterOut(new String[] { "rsa", "e", "n", "protected" }));
            byte[] aad = builder.build().toCanonicalForm();


            SExpression protectionKeyParameters = protectedKey.getExpression(2);
            SExpression s2kParams = protectionKeyParameters.getExpression(0);
            // TODO select correct hash
            S2K s2K = new S2K(PGPUtil.getDigestIDForName(s2kParams.getString(0)), s2kParams.getBytes(1), s2kParams.getInt(2));

            byte[] nonce = protectionKeyParameters.getBytes(1);

            PBESecretKeyDecryptor decryptor = keyProtectionRemoverFactory.createDecryptor("ocb");
            byte[] key = decryptor.makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_128, s2K);

            byte[] keyData = protectedKey.getBytes(3);


            return new UnwrapResult(SExpression.parse(
                ((PGPSecretKeyDecryptorWithAAD)decryptor).recoverKeyData(
                    SymmetricKeyAlgorithmTags.AES_128,
                    key, nonce, aad, keyData, 0, keyData.length),
                maxDepth).getExpression(0), s2K, Arrays.clone(nonce));

        }

        throw new PGPException("unhandled protection type " + protectionType);
    }

    /**
     * @param expression The expression (rsa (n ..) (e ..) ...)
     * @return
     */
    private PGPPublicKey getRSAPublicKey(SExpression expression, KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        BigInteger n = null;
        BigInteger e = null;
        for (Iterator it = expression.getValues().iterator(); it.hasNext();)
        {
            Object item = it.next();
            if (item instanceof SExpression)
            {
                SExpression exp = (SExpression)item;
                if (exp.hasLabel("e"))
                {
                    e = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                }
                else if (exp.hasLabel("n"))
                {
                    n = BigIntegers.fromUnsignedByteArray(exp.getBytes(1));
                }
            }
        }

        if (n == null || e == null)
        {
            return null;
        }

        PublicKeyPacket pubPacket = new PublicKeyPacket(PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), new RSAPublicBCPGKey(n, e));

        return new PGPPublicKey(pubPacket, fingerPrintCalculator);
    }

    /**
     * Encodes a public key into an S-Expression.
     * Used primarily where the public key is part the AAD value in OCB mode.
     *
     * @param publicKey The public key
     * @param builder   The SExpresson builder
     * @return the same builder as passed in.
     * @throws PGPException
     */
    private SExpression.Builder addPublicKey(PGPPublicKey publicKey, SExpression.Builder builder)
        throws PGPException
    {
        PublicKeyPacket publicPk = publicKey.getPublicKeyPacket();
        try
        {
            switch (publicPk.getAlgorithm())
            {


            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicBCPGKey dsaK = (DSAPublicBCPGKey)publicPk.getKey();


                return builder
                    .addValue(
                        SExpression.builder()
                            .addValue("p")
                            .addValue(dsaK.getP().toByteArray())
                            .build())
                    .addValue(SExpression.builder()
                        .addValue("q")
                        .addValue(dsaK.getQ().toByteArray())
                        .build())
                    .addValue(SExpression.builder()
                        .addValue("g")
                        .addValue(dsaK.getG().toByteArray())
                        .build())
                    .addValue(SExpression.builder()
                        .addValue("y")
                        .addValue(dsaK.getY().toByteArray())
                        .build());
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                Object k = publicPk.getKey();

                ECDHPublicBCPGKey ecdhK = (ECDHPublicBCPGKey)publicPk.getKey();

                if (ecdhK.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    byte[] pEnc = BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint());

                    // skip the 0x40 header byte.
                    if (pEnc.length < 1 || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }

                    throw new IllegalStateException("not implemented");

                }
                else
                {
                    throw new IllegalStateException("not implemented");
                }
            }

            case PublicKeyAlgorithmTags.ECDSA:
            {
                ECDSAPublicBCPGKey ecKey = (ECDSAPublicBCPGKey)publicPk.getKey();
                byte[] pEnc = BigIntegers.asUnsignedByteArray(ecKey.getEncodedPoint());


                return builder.addValue(
                    SExpression.builder()
                        .addValue("q")
                        .addValue(pEnc)
                        .build());
            }


            case PublicKeyAlgorithmTags.EDDSA_LEGACY:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();
                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                // skip the 0x40 header byte.
                if (pEnc.length < 1 || 0x40 != pEnc[0])
                {
                    throw new IllegalArgumentException("Invalid Ed25519 public key");
                }

                return builder.addValue(
                    SExpression.builder()
                        .addValue("q")
                        .addValue(pEnc)
                        .build());
            }

            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();
                throw new IllegalStateException("not implemented");
            }

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();

                return builder.addValue(
                    SExpression.builder()
                        .addValue("n")
                        .addValue(rsaK.getModulus().toByteArray())
                        .build()).addValue(
                    SExpression.builder()
                        .addValue("e")
                        .addValue(rsaK.getPublicExponent().toByteArray())
                        .build()
                );
            }

            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("exception constructing public key", e);
        }
    }

    private static class UnwrapResult
    {
        final SExpression expression;
        final S2K s2K;
        final byte[] iv;
        final Object metaData;

        public UnwrapResult(SExpression expression, S2K s2K, byte[] iv)
        {
            this.expression = expression;
            this.s2K = s2K;
            this.iv = iv;
            this.metaData = null;
        }

        public UnwrapResult(SExpression expression, S2K s2K, byte[] iv, Object metaData)
        {
            this.expression = expression;
            this.s2K = s2K;
            this.iv = iv;
            this.metaData = metaData;
        }

    }


    public static class Builder
    {
        private ArrayList<PGPExtendedKeyHeader> headerList = new ArrayList<PGPExtendedKeyHeader>();
        private SExpression keyExpression;

        public Builder setHeaderList(ArrayList<PGPExtendedKeyHeader> headerList)
        {
            this.headerList = headerList;
            return this;
        }

        public Builder setKeyExpression(SExpression keyExpression)
        {
            this.keyExpression = keyExpression;
            return this;
        }

        public OpenedPGPKeyData build()
        {
            return new OpenedPGPKeyData(headerList, keyExpression);
        }

        public void add(PGPExtendedKeyHeader pgpExtendedKeyHeader)
        {
            headerList.add(pgpExtendedKeyHeader);
        }
    }

}
