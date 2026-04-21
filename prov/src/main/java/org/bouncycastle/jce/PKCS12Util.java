package org.bouncycastle.jce;

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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;

/**
 * Utility class for re-encoding PKCS#12 files to definite length.
 */
public class PKCS12Util
{
    private static final BigInteger DEFAULT_MAX_IT_COUNT = BigInteger.valueOf(5000000);

    static final String PKCS12_MAX_IT_COUNT_PROPERTY = "org.bouncycastle.pkcs12.max_it_count";

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

    /**
     * Re-encode the PKCS#12 structure to definite length encoding at the inner layer
     * as well, recomputing the MAC accordingly.
     *
     * @param berPKCS12File - original PKCS12 file.
     * @param provider - provider to use for MAC calculation.
     * @return a byte array representing the DER encoding of the PFX structure.
     * @throws IOException on parsing, encoding errors.
     */
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
            throw new IOException("error constructing MAC: " + e.toString());
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

        BigInteger max = Properties.asBigInteger(PKCS12_MAX_IT_COUNT_PROPERTY);
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
            // TODO[pkcs12] PBMAC1 support, copy/share with PKCS12KeyStoreSpi.calculatePbeMac
            throw new UnsupportedOperationException();
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
}
