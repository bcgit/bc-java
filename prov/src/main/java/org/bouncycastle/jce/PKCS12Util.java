package org.bouncycastle.jce;

import java.io.IOException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

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
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * Utility class for reencoding PKCS#12 files to definite length.
 */
public class PKCS12Util
{
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
     * @param provider - provider to use for MAC calculation.
     * @return a byte array representing the DER encoding of the PFX structure.
     * @throws IOException on parsing, encoding errors.
     */
    public static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd, String provider)
        throws IOException
    {
        Pfx pfx = Pfx.getInstance(berPKCS12File);

        ContentInfo info = pfx.getAuthSafe();

        ASN1Primitive obj = ASN1Primitive.fromByteArray(getContentOctets(info));

        byte[] derEncoding = obj.getEncoded(ASN1Encoding.DER);

        info = new ContentInfo(info.getContentType(), new DEROctetString(derEncoding));

        MacData mData = pfx.getMacData();
        try
        {
            int itCount = mData.getIterationCount().intValue();
            byte[] data = getContentOctets(info);
            byte[] res = calculatePbeMac(mData.getMac().getAlgorithmId().getAlgorithm(), mData.getSalt(), itCount, passwd, data, provider);

            AlgorithmIdentifier algId = new AlgorithmIdentifier(mData.getMac().getAlgorithmId().getAlgorithm(), DERNull.INSTANCE);
            DigestInfo dInfo = new DigestInfo(algId, res);

            mData = new MacData(dInfo, mData.getSalt(), itCount);
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

    private static byte[] calculatePbeMac(
        ASN1ObjectIdentifier oid,
        byte[]              salt,
        int                 itCount,
        char[]              password,
        byte[]              data,
        String              provider)
        throws Exception
    {
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(oid.getId(), provider);
        PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        SecretKey key = keyFact.generateSecret(pbeSpec);

        Mac mac = Mac.getInstance(oid.getId(), provider);
        mac.init(key, defParams);
        mac.update(data);

        return mac.doFinal();
    }
}
