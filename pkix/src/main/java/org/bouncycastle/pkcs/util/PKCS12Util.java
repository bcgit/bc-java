package org.bouncycastle.pkcs.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * Utility class for re-encoding PKCS#12 files to definite length.
 * <p>
 * Replaces {@link org.bouncycastle.jce.PKCS12Util}; this class additionally
 * understands RFC 9579 PBMAC1 protected PFX files.
 * </p>
 */
public class PKCS12Util
{
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    /**
     * Just re-encode the outer layer of the PKCS#12 file to definite length encoding.
     *
     * @param berPKCS12File - original PKCS#12 file
     * @return a byte array representing the DER encoding of the PFX structure
     * @throws IOException
     */
    public static byte[] convertToDefiniteLength(byte[] berPKCS12File)
        throws IOException
    {
        Pfx pfx = Pfx.getInstance(berPKCS12File);

        return pfx.getEncoded(ASN1Encoding.DER);
    }

    /**
     * Re-encode the PKCS#12 structure to definite length encoding at the inner layer
     * as well, recomputing the MAC accordingly.
     *
     * @param berPKCS12File - original PKCS12 file.
     * @return a byte array representing the DER encoding of the PFX structure.
     * @throws IOException on parsing, encoding errors.
     */
    public static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd)
        throws IOException
    {
        return convertToDefiniteLength(berPKCS12File, passwd, new DefaultJcaJceHelper());
    }

    /**
     * Re-encode the PKCS#12 structure to definite length encoding at the inner layer
     * as well, recomputing the MAC accordingly.
     *
     * @param berPKCS12File - original PKCS12 file.
     * @param provider - provider name to use for MAC calculation.
     * @return a byte array representing the DER encoding of the PFX structure.
     * @throws IOException on parsing, encoding errors.
     */
    public static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd, String provider)
        throws IOException
    {
        return convertToDefiniteLength(berPKCS12File, passwd, new NamedJcaJceHelper(provider));
    }

    /**
     * Re-encode the PKCS#12 structure to definite length encoding at the inner layer
     * as well, recomputing the MAC accordingly.
     *
     * @param berPKCS12File - original PKCS12 file.
     * @param provider - provider to use for MAC calculation.
     * @return a byte array representing the DER encoding of the PFX structure.
     * @throws IOException on parsing, encoding errors.
     */
    public static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd, Provider provider)
        throws IOException
    {
        return convertToDefiniteLength(berPKCS12File, passwd, new ProviderJcaJceHelper(provider));
    }

    private static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd, JcaJceHelper helper)
        throws IOException
    {
        Pfx pfx = Pfx.getInstance(berPKCS12File);

        ContentInfo info = pfx.getAuthSafe();

        ASN1Primitive obj = ASN1Primitive.fromByteArray(getContentOctets(info));

        byte[] contentOctets = obj.getEncoded(ASN1Encoding.DER);

        info = new ContentInfo(info.getContentType(), DEROctetString.withContents(contentOctets));

        MacData mData = pfx.getMacData();
        try
        {
            AlgorithmIdentifier macAlgID = mData.getMac().getAlgorithmId();
            byte[] salt = mData.getSalt();
            int itCount = validateIterationCount(mData.getIterationCount());
            byte[] res = calculatePbeMac(helper, macAlgID, salt, itCount, passwd, contentOctets);

            // Avoid replacing e.g. PBMAC1 parameters
            if (macAlgID.getParameters() == null)
            {
                macAlgID = new AlgorithmIdentifier(macAlgID.getAlgorithm(), DERNull.INSTANCE);
            }

            DigestInfo dInfo = new DigestInfo(macAlgID, res);

            mData = new MacData(dInfo, salt, itCount);
        }
        catch (Exception e)
        {
            throw Exceptions.ioException("error constructing MAC: " + e.toString(), e);
        }

        pfx = new Pfx(info, mData);

        return pfx.getEncoded(ASN1Encoding.DER);
    }

    public static ASN1Encodable getContent(ContentInfo contentInfo) throws IOException
    {
        ASN1Encodable content = contentInfo.getContent();
        if (content == null)
        {
            throw new ASN1ParsingException("ContentInfo content missing");
        }

        return content;
    }

    public static byte[] getContentOctets(ContentInfo contentInfo) throws IOException
    {
        return ASN1OctetString.getInstance(getContent(contentInfo)).getOctets();
    }

    public static ASN1OctetString getEncryptedContent(EncryptedData encryptedData) throws IOException
    {
        ASN1OctetString content = encryptedData.getContent();
        if (content == null)
        {
            throw new ASN1ParsingException("EncryptedContentInfo content missing");
        }

        return content;
    }

    public static int validateIterationCount(BigInteger ic)
    {
        if (ic.signum() < 0)
        {
            throw new IllegalStateException("negative iteration count found");
        }
        if (ic.bitLength() > 31)
        {
            throw new IllegalStateException("iteration counts >= 2^31 are not suppported");
        }

        BigInteger max = Properties.asBigInteger(Properties.PKCS12_MAX_IT_COUNT);
        if (max == null)
        {
            max = DEFAULT_MAX_IT_COUNT;
        }

        if (ic.compareTo(max) > 0)
        {
            throw new IllegalStateException("iteration count " + ic + " greater than " + max);
        }

        return BigIntegers.intValueExact(ic);
    }

    private static byte[] calculatePbeMac(
        JcaJceHelper        helper,
        AlgorithmIdentifier macAlgID,
        byte[]              salt,
        int                 itCount,
        char[]              password,
        byte[]              data)
        throws Exception
    {
        ASN1ObjectIdentifier oid = macAlgID.getAlgorithm();

        if (PKCSObjectIdentifiers.id_PBMAC1.equals(oid))
        {
            return calculatePBMAC1(macAlgID, password, data);
        }

        PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);

        SecretKeyFactory keyFact = helper.createSecretKeyFactory(oid.getId());
        SecretKey key = keyFact.generateSecret(new PBEKeySpec(password));

        try
        {
            Mac mac = helper.createMac(oid.getId());

            mac.init(key, defParams);
            mac.update(data);

            return mac.doFinal();
        }
        finally
        {
            try
            {
                if (key != null)
                {
                    key.destroy();
                }
            }
            catch (DestroyFailedException e)
            {
                // ignore
            }
        }
    }

    private static byte[] calculatePBMAC1(AlgorithmIdentifier macAlgID, char[] password, byte[] data)
        throws IOException
    {
        PBMAC1Params pbmac1Params = PBMAC1Params.getInstance(macAlgID.getParameters());
        if (pbmac1Params == null)
        {
            throw new IOException("If the DigestAlgorithmIdentifier is id-PBMAC1, then the parameters field must contain valid PBMAC1-params parameters.");
        }
        if (!PKCSObjectIdentifiers.id_PBKDF2.equals(pbmac1Params.getKeyDerivationFunc().getAlgorithm()))
        {
            throw new IOException("Unsupported PBMAC1 key derivation function: " + pbmac1Params.getKeyDerivationFunc().getAlgorithm());
        }

        PBKDF2Params pbkdf2Params = PBKDF2Params.getInstance(pbmac1Params.getKeyDerivationFunc().getParameters());
        if (pbkdf2Params.getKeyLength() == null)
        {
            throw new IOException("Key length must be present when using PBMAC1.");
        }

        HMac hMac = new HMac(getPrf(pbmac1Params.getMessageAuthScheme().getAlgorithm()));
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator(getPrf(pbkdf2Params.getPrf().getAlgorithm()));

        generator.init(
            Strings.toUTF8ByteArray(password),
            pbkdf2Params.getSalt(),
            validateIterationCount(pbkdf2Params.getIterationCount()));

        CipherParameters key = generator.generateDerivedParameters(BigIntegers.intValueExact(pbkdf2Params.getKeyLength()) * 8);

        Arrays.clear(generator.getPassword());

        hMac.init(key);
        hMac.update(data, 0, data.length);
        byte[] res = new byte[hMac.getMacSize()];
        hMac.doFinal(res, 0);
        return res;
    }

    private static Digest getPrf(ASN1ObjectIdentifier prfId)
    {
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(prfId))
        {
            return new SHA256Digest();
        }
        if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(prfId))
        {
            return new SHA512Digest();
        }
        throw new IllegalArgumentException("unknown prf id " + prfId);
    }
}
