package org.bouncycastle.jcajce.provider.test.jasypt;

/**
 * Thrown when a Decoder has encountered a failure condition during a decode.
 *
 * @author Apache Software Foundation
 */
public class DecoderException extends Exception {

    /**
     * Creates a DecoderException
     *
     * @param pMessage A message with meaning to a human
     */
    public DecoderException(String pMessage) {
        super(pMessage);
    }

}
