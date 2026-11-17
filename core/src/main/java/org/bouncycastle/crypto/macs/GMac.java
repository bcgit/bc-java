package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;


/**
 * The GMAC specialisation of Galois/Counter mode (GCM) detailed in NIST Special Publication
 * 800-38D.
 * <p>
 * GMac is an invocation of the GCM mode where no data is encrypted (i.e. all input data to the Mac
 * is processed as additional authenticated data with the underlying GCM block cipher).
 * <p>
 * A GMAC tag is a function of the key and nonce masking a hash of the input, so two tags under one
 * key and nonce over different inputs allow forgeries: each message needs a fresh nonce through
 * {@link #init}. After the first tag under a nonce, a further {@link #doFinal} (with or without a
 * {@link #reset}) is accepted only for the identical input, for which it returns the same tag; any
 * other input is refused with an IllegalStateException. The check is the underlying cipher's
 * verification of that tag in decryption mode.
 */
public class GMac implements Mac
{
    private final GCMModeCipher cipher;
    private int macSizeBits;

    // the parameters the cipher was last initialised with, and the tag produced under them, if any
    private AEADParameters parameters;
    private byte[] tag;

    /**
     * Creates a GMAC based on the operation of a block cipher in GCM mode.
     * <p>
     * This will produce an authentication code the length of the block size of the cipher.
     * 
     * @param cipher
     *            the cipher to be used in GCM mode to generate the MAC.
     */
    public GMac(final GCMModeCipher cipher)
    {
        // use of this confused flow analyser in some earlier JDKs
        this.cipher = cipher;
        this.macSizeBits = 128;
    }

    /**
     * Creates a GMAC based on the operation of a 128 bit block cipher in GCM mode.
     * 
     * @param macSizeBits
     *            the mac size to generate, in bits. Must be a multiple of 8 and &gt;= 32 and &lt;= 128.
     *            Sizes less than 96 are not recommended, but are supported for specialized applications.
     * @param cipher
     *            the cipher to be used in GCM mode to generate the MAC.
     */
    public GMac(final GCMModeCipher cipher, final int macSizeBits)
    {
        this.cipher = cipher;
        this.macSizeBits = macSizeBits;
    }

    /**
     * Initialises the GMAC - requires either a {@link ParametersWithIV} providing a
     * {@link KeyParameter} and a nonce, or an {@link AEADParameters} carrying the key, nonce and
     * desired MAC size. When {@link AEADParameters} are supplied the MAC size they carry overrides
     * the one passed to the constructor (this is the form used by RFC 9044 AES-GMAC, whose
     * GMACParameters allow a 12 to 16 octet tag).
     */
    public void init(final CipherParameters params) throws IllegalArgumentException
    {
        if (params instanceof AEADParameters)
        {
            final AEADParameters param = (AEADParameters)params;

            this.macSizeBits = param.getMacSize();

            // GCM is always operated in encrypt mode to calculate MAC
            cipher.init(true, param);
            this.parameters = param;
            this.tag = null;
        }
        else if (params instanceof ParametersWithIV)
        {
            final ParametersWithIV param = (ParametersWithIV)params;

            final byte[] iv = param.getIV();
            final KeyParameter keyParam = (KeyParameter)param.getParameters();

            // GCM is always operated in encrypt mode to calculate MAC
            AEADParameters aeadParam = new AEADParameters(keyParam, macSizeBits, iv);
            cipher.init(true, aeadParam);
            this.parameters = aeadParam;
            this.tag = null;
        }
        else
        {
            throw new IllegalArgumentException("GMAC requires ParametersWithIV or AEADParameters");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getUnderlyingCipher().getAlgorithmName() + "-GMAC";
    }

    public int getMacSize()
    {
        return macSizeBits / 8;
    }

    public void update(byte in) throws IllegalStateException
    {
        cipher.processAADByte(in);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        cipher.processAADBytes(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (tag == null)
        {
            int len;
            try
            {
                len = cipher.doFinal(out, outOff);
            }
            catch (InvalidCipherTextException e)
            {
                // Impossible in encrypt mode
                throw new IllegalStateException(e.toString());
            }
            tag = Arrays.copyOfRange(out, outOff, outOff + len);
            // from here on the cipher verifies the input against this tag
            cipher.init(false, parameters);
            return len;
        }

        if (outOff > out.length - tag.length)
        {
            throw new OutputLengthException("output buffer too short");
        }
        try
        {
            cipher.processBytes(tag, 0, tag.length, new byte[tag.length], 0);
            cipher.doFinal(new byte[tag.length], 0);
        }
        catch (InvalidCipherTextException e)
        {
            cipher.reset();
            throw new IllegalStateException("GMAC cannot be reused with the same nonce over different data");
        }
        System.arraycopy(tag, 0, out, outOff, tag.length);
        return tag.length;
    }

    public void reset()
    {
        cipher.reset();
    }
}
