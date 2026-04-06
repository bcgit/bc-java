package org.bouncycastle.crypto.hash2curve;

/**
 * The MessageExpansion interface defines a contract for expanding a message.
 */
public interface MessageExpansion {

  /**
   * Expands the given message to match the specified length in bytes.
   *
   * @param msg the original message to be expanded
   * @param dst domain separation tag
   * @param lenInBytes the desired length of the expanded message in bytes
   * @return the expanded message as a byte array
   */
  byte[] expandMessage(byte[] msg, byte[] dst, int lenInBytes);

}
