package org.bouncycastle.crypto.modes;

public interface CCMModeCipher
    extends AEADBlockCipher
{
    // TODO Add these so that all usages of CCMBlockCipher can be replaced by CCMModeCipher
//    byte[] processPacket(byte[] in, int inOff, int inLen)
//        throws IllegalStateException, InvalidCipherTextException;
//
//    int processPacket(byte[] in, int inOff, int inLen, byte[] output, int outOff)
//        throws IllegalStateException, InvalidCipherTextException, DataLengthException;
}
