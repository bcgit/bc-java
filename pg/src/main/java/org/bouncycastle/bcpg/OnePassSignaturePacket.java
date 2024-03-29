package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * generic signature object
 */
public class OnePassSignaturePacket 
    extends ContainedPacket
{
    private int  version;
    private int  sigType;
    private int  hashAlgorithm;
    private int  keyAlgorithm;
    private long keyID;
    private int isContaining;
    
    OnePassSignaturePacket(
        BCPGInputStream    in)
        throws IOException
    {
        super(ONE_PASS_SIGNATURE);

        version = in.read();
        sigType = in.read();
        hashAlgorithm = in.read();
        keyAlgorithm = in.read();
        
        keyID |= (long)in.read() << 56;
        keyID |= (long)in.read() << 48;
        keyID |= (long)in.read() << 40;
        keyID |= (long)in.read() << 32;
        keyID |= (long)in.read() << 24;
        keyID |= (long)in.read() << 16;
        keyID |= (long)in.read() << 8;
        keyID |= in.read();
        
        isContaining = in.read();
    }
    
    public OnePassSignaturePacket(
        int        sigType,
        int        hashAlgorithm,
        int        keyAlgorithm,
        long       keyID,
        boolean    isNested)
    {
        super(ONE_PASS_SIGNATURE);

        this.version = 3;
        this.sigType = sigType;
        this.hashAlgorithm = hashAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keyID = keyID;
        this.isContaining = (isNested) ? 0 : 1;
    }
    
    /**
     * Return the signature type.
     * @return the signature type
     */
    public int getSignatureType()
    {
        return sigType;
    }
    
    /**
     * return the encryption algorithm tag
     */
    public int getKeyAlgorithm()
    {
        return keyAlgorithm;
    }
    
    /**
     * return the hashAlgorithm tag
     */
    public int getHashAlgorithm()
    {
        return hashAlgorithm;
    }
    
    /**
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }

    /**
     * Return true, if the signature contains any signatures that follow.
     * An bracketing OPS is followed by additional OPS packets and is calculated over all the data between itself
     * and its corresponding signature (it is an attestation for encapsulated signatures).
     *
     * @return true if encapsulating, false otherwise
     */
    public boolean isContaining()
    {
        return isContaining == 1;
    }
    
    /**
     * 
     */
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream            pOut = new BCPGOutputStream(bOut);
  
        pOut.write(version);
        pOut.write(sigType);
        pOut.write(hashAlgorithm);
        pOut.write(keyAlgorithm);

        StreamUtil.writeKeyID(pOut, keyID);

        pOut.write(isContaining);

        pOut.close();

        out.writePacket(ONE_PASS_SIGNATURE, bOut.toByteArray());
    }

}
