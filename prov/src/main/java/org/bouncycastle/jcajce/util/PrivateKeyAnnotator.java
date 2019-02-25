package org.bouncycastle.jcajce.util;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for instancing AnnotatedPrivateKeys.
 */
public class PrivateKeyAnnotator
{
    /**
     * Create an AnnotatedPrivateKey with a single annotation using AnnotatedPrivateKey.LABEL as a key.
     *
     * @param privKey the private key to be annotated.
     * @param label the label to be associated with the private key.
     * @return the newly annotated private key.
     */
    public static AnnotatedPrivateKey annotate(PrivateKey privKey, String label)
    {
        return new AnnotatedPrivateKey(privKey, label);
    }

    public static AnnotatedPrivateKey annotate(PrivateKey privKey, Map<String, Object> annotations)
    {
        Map savedAnnotations = new HashMap(annotations);

        return new AnnotatedPrivateKey(privKey, Collections.unmodifiableMap(savedAnnotations));
    }
}
