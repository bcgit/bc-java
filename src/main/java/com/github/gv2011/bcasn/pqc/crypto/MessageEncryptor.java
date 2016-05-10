package com.github.gv2011.bcasn.pqc.crypto;


import com.github.gv2011.bcasn.crypto.CipherParameters;

public interface MessageEncryptor
{

    /**
     *
     * @param forEncrypting true if we are encrypting a signature, false
     * otherwise.
     * @param param key parameters for encryption or decryption.
     */
    public void init(boolean forEncrypting, CipherParameters param);

    /**
     *
     * @param message the message to be signed.
     * @throws Exception 
     */
    public byte[] messageEncrypt(byte[] message) throws Exception;

    /**
     *
     * @param cipher the cipher text of the message
     * @throws Exception 
     */
    public byte[] messageDecrypt(byte[] cipher) throws Exception;
}
