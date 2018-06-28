package org.bouncycastle.cert.crmf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.KeyWrapper;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.util.Strings;

/**
 * Builder for EncryptedValue structures.
 */
public class EncryptedValueBuilder
{
    private KeyWrapper wrapper;
    private OutputEncryptor encryptor;
    private EncryptedValuePadder padder;

    /**
     * Create a builder that makes EncryptedValue structures.
     *
     * @param wrapper a wrapper for key used to encrypt the actual data contained in the EncryptedValue.
     * @param encryptor  an output encryptor to encrypt the actual data contained in the EncryptedValue. 
     */
    public EncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor)
    {
        this(wrapper, encryptor, null);
    }

    /**
     * Create a builder that makes EncryptedValue structures with fixed length blocks padded using the passed in padder.
     *
     * @param wrapper a wrapper for key used to encrypt the actual data contained in the EncryptedValue.
     * @param encryptor  an output encryptor to encrypt the actual data contained in the EncryptedValue.
     * @param padder a padder to ensure that the EncryptedValue created will always be a constant length.
     */
    public EncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor, EncryptedValuePadder padder)
    {
        this.wrapper = wrapper;
        this.encryptor = encryptor;
        this.padder = padder;
    }

    /**
     * Build an EncryptedValue structure containing the passed in pass phrase.
     *
     * @param revocationPassphrase  a revocation pass phrase.
     * @return an EncryptedValue containing the encrypted pass phrase.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(char[] revocationPassphrase)
        throws CRMFException
    {
        return encryptData(padData(Strings.toUTF8ByteArray(revocationPassphrase)));
    }

    /**
     * Build an EncryptedValue structure containing the certificate contained in
     * the passed in holder.
     *
     * @param holder  a holder containing a certificate.
     * @return an EncryptedValue containing the encrypted certificate.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(X509CertificateHolder holder)
        throws CRMFException
    {
        try
        {
            return encryptData(padData(holder.getEncoded()));
        }
        catch (IOException e)
        {
            throw new CRMFException("cannot encode certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Build an EncryptedValue structure containing the private key contained in
     * the passed info structure.
     *
     * @param privateKeyInfo  a PKCS#8 private key info structure.
     * @return an EncryptedValue containing an EncryptedPrivateKeyInfo structure.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(PrivateKeyInfo privateKeyInfo)
        throws CRMFException
    {
        PKCS8EncryptedPrivateKeyInfoBuilder encInfoBldr = new PKCS8EncryptedPrivateKeyInfoBuilder(privateKeyInfo);

        AlgorithmIdentifier intendedAlg = privateKeyInfo.getPrivateKeyAlgorithm();
        AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
        DERBitString encSymmKey;

        try
        {
            PKCS8EncryptedPrivateKeyInfo encInfo = encInfoBldr.build(encryptor);
            
            encSymmKey = new DERBitString(wrapper.generateWrappedKey(encryptor.getKey()));

            AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();
            ASN1OctetString valueHint = null;

            return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, new DERBitString(encInfo.getEncryptedData()));
        }
        catch (IllegalStateException e)
        {
            throw new CRMFException("cannot encode key: " + e.getMessage(), e);
        }
        catch (OperatorException e)
        {
            throw new CRMFException("cannot wrap key: " + e.getMessage(), e);
        }
    }

    private EncryptedValue encryptData(byte[] data)
       throws CRMFException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream eOut = encryptor.getOutputStream(bOut);

        try
        {
            eOut.write(data);

            eOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("cannot process data: " + e.getMessage(), e);
        }

        AlgorithmIdentifier intendedAlg = null;
        AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
        DERBitString encSymmKey;

        try
        {
            wrapper.generateWrappedKey(encryptor.getKey());
            encSymmKey = new DERBitString(wrapper.generateWrappedKey(encryptor.getKey()));
        }
        catch (OperatorException e)
        {
            throw new CRMFException("cannot wrap key: " + e.getMessage(), e);
        }

        AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();
        ASN1OctetString valueHint = null;
        DERBitString encValue = new DERBitString(bOut.toByteArray());

        return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);
    }

    private byte[] padData(byte[] data)
    {
        if (padder != null)
        {
            return padder.getPaddedData(data);
        }

        return data;
    }
}
