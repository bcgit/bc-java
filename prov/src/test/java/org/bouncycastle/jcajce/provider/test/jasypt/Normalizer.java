/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.bouncycastle.jcajce.provider.test.jasypt;

import java.lang.reflect.Field;
import java.lang.reflect.Method;


/**
 * <p>
 * Utility for the normalization of Unicode Strings to NFC form. 
 * </p>
 * <p>
 * This class tries to use the <tt>java.text.Normalizer</tt> class in JDK 1.6
 * first and, if it the class is not found (Java version < 6), then it will use
 * the ICU4J <tt>com.ibm.icu.text.Normalizer</tt> class (in this case, a
 * <tt>ClassNotFoundException</tt> will be thrown if ICU4J is not present).
 * </p>
 * 
 * @since 1.5
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class Normalizer
{

    private static final String ICU_NORMALIZER_CLASS_NAME = "com.ibm.icu.text.Normalizer";
    private static final String JDK_NORMALIZER_CLASS_NAME = "java.text.Normalizer";
    private static final String JDK_NORMALIZER_FORM_CLASS_NAME = "java.text.Normalizer$Form";
    
    private static Boolean useIcuNormalizer = null;
    
    private static Method javaTextNormalizerMethod = null;
    private static Object javaTextNormalizerFormNFCConstant = null;

    
    /**
     * <p>
     *   Normalize Unicode-input message to NFC.
     * </p>
     * <p>
     *   This algorithm will first try to normalize the input's UNICODE using icu4j's 
     *   <tt>com.ibm.icu.text.Normalizer</tt> and, if it is not present at the
     *   classpath, will try to use <tt>java.text.Normalizer</tt>. If this is not present
     *   either (this class appeared in JavaSE 6), it will raise an exception.
     * </p>
     * 
     * @param message the message to be normalized
     * @return the result of the normalization operation
     */
    public static String normalizeToNfc(final String message) {
        return new String(normalizeToNfc(message.toCharArray()));
    }

    
    /**
     * <p>
     *   Normalize Unicode-input message to NFC.
     * </p>
     * <p>
     *   This algorithm will first try to normalize the input's UNICODE using icu4j's 
     *   <tt>com.ibm.icu.text.Normalizer</tt> and, if it is not present at the
     *   classpath, will try to use <tt>java.text.Normalizer</tt>. If this is not present
     *   either (this class appeared in JavaSE 6), it will raise an exception.
     * </p>
     * 
     * @param message the message to be normalized
     * @return the result of the normalization operation
     */
    public static char[] normalizeToNfc(final char[] message) {
        
        if (useIcuNormalizer == null) {
            // Still not initialized, will try to load the icu4j Normalizer. If 
            // icu4j is in the classpath, it will be used even if java version is >= 6.
            try {
                
                initializeIcu4j();
                
            } catch (final ClassNotFoundException e) {
                
                try {
                    
                    initializeJavaTextNormalizer();
                    
                } catch (final ClassNotFoundException e2) {
                    throw new EncryptionInitializationException(
                            "Cannot find a valid UNICODE normalizer: neither " + JDK_NORMALIZER_CLASS_NAME + " nor " +
                            ICU_NORMALIZER_CLASS_NAME + " have been found at the classpath. If you are using " +
                            "a version of the JDK older than JavaSE 6, you should include the icu4j library in " + 
                            "your classpath.");
                } catch (final NoSuchMethodException e2) {
                    throw new EncryptionInitializationException(
                            "Cannot find a valid UNICODE normalizer: " + JDK_NORMALIZER_CLASS_NAME + " has " +
                            "been found at the classpath, but has an incompatible signature for its 'normalize' " +
                            "method.");
                } catch (final NoSuchFieldException e2) {
                    throw new EncryptionInitializationException(
                            "Cannot find a valid UNICODE normalizer: " + JDK_NORMALIZER_FORM_CLASS_NAME + " has " +
                            "been found at the classpath, but seems to have no 'NFC' value.");
                } catch (final IllegalAccessException e2) {
                    throw new EncryptionInitializationException(
                            "Cannot find a valid UNICODE normalizer: " + JDK_NORMALIZER_FORM_CLASS_NAME + " has " +
                            "been found at the classpath, but seems to have no 'NFC' value.");
                }
                
            }
        }
        
        if (useIcuNormalizer.booleanValue()) {
            return normalizeWithIcu4j(message);
        }
        
        return normalizeWithJavaNormalizer(message);
        
    }


    
    static void initializeIcu4j() throws ClassNotFoundException {
        Thread.currentThread().getContextClassLoader().loadClass(ICU_NORMALIZER_CLASS_NAME);
        useIcuNormalizer = Boolean.TRUE;
    }


    
    static void initializeJavaTextNormalizer() 
            throws ClassNotFoundException, NoSuchMethodException, NoSuchFieldException, IllegalAccessException {
    
        final Class javaTextNormalizerClass = 
                Thread.currentThread().getContextClassLoader().loadClass(JDK_NORMALIZER_CLASS_NAME);
        final Class javaTextNormalizerFormClass = 
                Thread.currentThread().getContextClassLoader().loadClass(JDK_NORMALIZER_FORM_CLASS_NAME);
        javaTextNormalizerMethod =
                javaTextNormalizerClass.getMethod(
                        "normalize", new Class[]{ CharSequence.class, javaTextNormalizerFormClass });
        final Field javaTextNormalizerFormNFCConstantField = javaTextNormalizerFormClass.getField("NFC");
        javaTextNormalizerFormNFCConstant = javaTextNormalizerFormNFCConstantField.get(null);
        
        useIcuNormalizer = Boolean.FALSE;
        
    }
    
    
    
    
    static char[] normalizeWithJavaNormalizer(final char[] message) {
        
        if (javaTextNormalizerMethod == null || javaTextNormalizerFormNFCConstant == null) {
            throw new EncryptionInitializationException(
                "Cannot use: " + JDK_NORMALIZER_FORM_CLASS_NAME + ", as JDK-based normalization has " +
                "not been initialized! (check previous execution errors)");
        }
            
        // Using java JDK's Normalizer, we cannot avoid creating Strings
        // (it is the only possible interface to the Normalizer class).
        //
        // Note java.text.Normalizer is accessed via reflection in order to allow this
        // class to be JDK 1.4-compilable (though ICU4j will be needed at runtime
        // if Java 1.4 is used).
        final String messageStr = new String(message);
        final String result;
        try {
            result = (String) javaTextNormalizerMethod.invoke(
                    null, new Object[] { messageStr, javaTextNormalizerFormNFCConstant });
        } catch (final Exception e) {
            throw new EncryptionInitializationException(
                    "Could not perform a valid UNICODE normalization", e);
        }
        return result.toCharArray();
    }

    
    static char[] normalizeWithIcu4j(final char[] message) {
        // initialize the result to twice the size of the message
        // this should be more than enough in most cases
        char[] normalizationResult = new char[message.length * 2];
        int normalizationResultSize = 0;
        while(true) {
            // Execute normalization. The result will be written into the normalizationResult
            // char array, and the returned int will be the real size of the result. Normally,
            // this will be smaller than the size of normalizationResult, but if it is bigger,
            // we will have to create a new normalizationResult array and try again (icu4j will
            // not raise an exception, only return a value bigger than the destination array size).
            normalizationResultSize = 0;
            throw new IllegalStateException("Not implemented");
                //normalize(message, normalizationResult, new NFCMode(), 0);
//            if (normalizationResultSize <= normalizationResult.length) {
//                // everything went OK and result fitted. Copy to a correctly-sized array
//                // and clean normalizationResult
//                final char[] result = new char[normalizationResultSize];
//                System.arraycopy(normalizationResult, 0, result, 0, normalizationResultSize);
//                for (int i = 0; i < normalizationResult.length; i++) {
//                    normalizationResult[i] = (char)0;
//                }
//                return result;
//            }
//            // We need a bigger array. the old array must be cleaned also
//            for (int i = 0; i < normalizationResult.length; i++) {
//                normalizationResult[i] = (char)0;
//            }
//            normalizationResult = new char[normalizationResultSize];
        }
        
    }
    
    
    
    private Normalizer() {
        super();
    }
    
}
