package org.bouncycastle.crypto.hash2curve;

import java.math.BigInteger;

/**
 * Interface for Hash To Field
 */
public interface HashToField {

  /**
   * Processes the provided message two a two-dimensional field as defined
   * by the hash2curve specification
   *
   * @param message the input byte array representing the message to process
   * @return a two-dimensional {@link BigInteger} array as the result of the processing
   */
  BigInteger[][] process(byte[] message);

}
