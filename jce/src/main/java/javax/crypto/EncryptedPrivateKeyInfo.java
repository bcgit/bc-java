package javax.crypto;

import java.io.*;

import java.security.*;
import java.security.spec.*;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * This class implements the <code>EncryptedPrivateKeyInfo</code> type
 *  as defined in PKCS #8.
 * <p>Its ASN.1 definition is as follows:
 * 
 * <pre>
 * EncryptedPrivateKeyInfo ::=  SEQUENCE {
 *     encryptionAlgorithm   AlgorithmIdentifier,
 *     encryptedData   OCTET STRING }
 * 
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *     algorithm              OBJECT IDENTIFIER,
 *     parameters             ANY DEFINED BY algorithm OPTIONAL  }
 * </pre>
 */
public class EncryptedPrivateKeyInfo
{
    private org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo infoObj;
    private AlgorithmParameters algP;

    /*
     * Constructs (i.e., parses) an <code>EncryptedPrivateKeyInfo</code> from
     * its ASN.1 encoding.
     *
     * @param encoded the ASN.1 encoding of this object.
     * @exception NullPointerException if the <code>encoded</code> is null.
     * @exception IOException if error occurs when parsing the ASN.1 encoding.
     */
    public EncryptedPrivateKeyInfo(
        byte[] encoded)
        throws NullPointerException, IOException
    {
        if (encoded == null)
        {
            throw new NullPointerException("parameters null");
        }

        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoded);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);

        infoObj = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getInstance((ASN1Sequence)dIn.readObject());

        try
        {
            algP = this.getParameters();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IOException("can't create parameters: " + e.toString());
        }
    }

    /*
     * Constructs an <code>EncryptedPrivateKeyInfo</code> from the
     * encryption algorithm name and the encrypted data.
     * <p>Note: the <code>encrypedData</code> is cloned when constructing
     * this object.
     * <p>
     * If encryption algorithm has associated parameters use the constructor
     * with AlgorithmParameters as the parameter.
     *
     * @param algName algorithm name.
     * @param encryptedData encrypted data.
     * @exception NullPointerException if <code>algName</code> or <code>encryptedData</code> is null.
     * @exception IllegalArgumentException if <code>encryptedData</code> is empty, i.e. 0-length.
     * @exception NoSuchAlgorithmException if the specified algName is not supported.
     */
    public EncryptedPrivateKeyInfo(
        String algName,
        byte[] encryptedData)
        throws NullPointerException, IllegalArgumentException, NoSuchAlgorithmException
    {
        if (algName == null || encryptedData == null)
        {
            throw new NullPointerException("parameters null");
        }

        org.bouncycastle.asn1.x509.AlgorithmIdentifier      kAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algName), null);

        infoObj = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(kAlgId, (byte[])encryptedData.clone());
        algP = this.getParameters();
    }

    /**
     * Constructs an <code>EncryptedPrivateKeyInfo</code> from the
     * encryption algorithm parameters and the encrypted data.
     * <p>Note: the <code>encrypedData</code> is cloned when constructing
     * this object.
     *
     * @param algParams the algorithm parameters for the encryption 
     * algorithm. <code>algParams.getEncoded()</code> should return
     * the ASN.1 encoded bytes of the <code>parameters</code> field
     * of the <code>AlgorithmIdentifer</code> component of the
     * <code>EncryptedPrivateKeyInfo</code> type.
     * @param encryptedData encrypted data.
     * @exception NullPointerException if <code>algParams</code> or <code>encryptedData</code> is null.
     * @exception IllegalArgumentException if <code>encryptedData</code> is empty, i.e. 0-length.
     * @exception NoSuchAlgorithmException if the specified algName of the specified <code>algParams</code> parameter is not supported.
     */
    public EncryptedPrivateKeyInfo(
        AlgorithmParameters algParams,
        byte[]              encryptedData)
        throws NullPointerException, IllegalArgumentException, NoSuchAlgorithmException
    {
        if (algParams == null || encryptedData == null)
        {
            throw new NullPointerException("parameters null");
        }

        org.bouncycastle.asn1.x509.AlgorithmIdentifier      kAlgId = null;

        try
        {
            ByteArrayInputStream    bIn = new ByteArrayInputStream(algParams.getEncoded());
            ASN1InputStream          dIn = new ASN1InputStream(bIn);

            kAlgId = new AlgorithmIdentifier(
                    new ASN1ObjectIdentifier(algParams.getAlgorithm()), dIn.readObject());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error in encoding: " + e.toString());
        }

        infoObj = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(kAlgId, (byte[])encryptedData.clone());
        algP = this.getParameters();
    }

    /**
     * Returns the encryption algorithm.
     *
     * @returns the algorithm name.
     */
    public String getAlgName()
    {
        return infoObj.getEncryptionAlgorithm().getAlgorithm().getId();
    }

    private AlgorithmParameters getParameters()
        throws NoSuchAlgorithmException
    {
        AlgorithmParameters     ap = AlgorithmParameters.getInstance(this.getAlgName());
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream         dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);

        try
        {
            dOut.writeObject(infoObj.getEncryptionAlgorithm().getParameters());
            dOut.close();

            ap.init(bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new NoSuchAlgorithmException("unable to parse parameters");
        }

        return ap;
    }

    /**
     * Returns the algorithm parameters used by the encryption algorithm.
     *
     * @returns the algorithm parameters.
     */
    public AlgorithmParameters getAlgParameters()
    {
        return algP;
    }

    /**
     * Returns a copy of the encrypted data.
     *
     * @returns a copy of the encrypted data.
     */
    public byte[] getEncryptedData()
    {
        return infoObj.getEncryptedData();
    }

    /**
     * Extract the enclosed PKCS8EncodedKeySpec object from the 
     * encrypted data and return it.
     *
     * @return the PKCS8EncodedKeySpec object.
     * @exception InvalidKeySpecException if the given cipher is 
     * inappropriate for the encrypted data or the encrypted
     * data is corrupted and cannot be decrypted.
     */
    public PKCS8EncodedKeySpec getKeySpec(
        Cipher  c)
    throws InvalidKeySpecException
    {
        try
        {
            return new PKCS8EncodedKeySpec(c.doFinal(this.getEncryptedData()));
        }
        catch (Exception e)
        {
            throw new InvalidKeySpecException("can't get keySpec: " + e.toString());
        }
    }

    /**
     * Returns the ASN.1 encoding of this object.
     *
     * @returns the ASN.1 encoding.
     * @throws IOException if error occurs when constructing its ASN.1 encoding.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream         dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);

        dOut.writeObject(infoObj);
        dOut.close();

        return bOut.toByteArray();
    }
}
