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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <p>
 * Common utils regarding treatment of parameter values and encoding operations.
 * <b>This class is for internal use only</b>. 
 * </p> 
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class CommonUtils
{

    public static final String STRING_OUTPUT_TYPE_BASE64 = "base64"; 
    public static final String STRING_OUTPUT_TYPE_HEXADECIMAL = "hexadecimal"; 
    
    private static final List STRING_OUTPUT_TYPE_HEXADECIMAL_NAMES =
        Arrays.asList(
            new String[] {
                "HEXADECIMAL", "HEXA", "0X", "HEX", "HEXADEC"
            }
        );
    
    private static char[] hexDigits = 
        {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    

    
    
    public static Boolean getStandardBooleanValue(final String valueStr) {
        if (valueStr == null) {
            return null;
        }
        final String upperValue = valueStr.toUpperCase();
        if ("TRUE".equals(upperValue) || "ON".equals(upperValue) || "YES".equals(upperValue)) {
            return Boolean.TRUE;
        }
        if ("FALSE".equals(upperValue) || "OFF".equals(upperValue) || "NO".equals(upperValue)) {
            return Boolean.FALSE;
        }
        return null;
    }
    
    
    public static String getStandardStringOutputType(final String valueStr) {
        if (valueStr == null) {
            return null;
        }
        if (STRING_OUTPUT_TYPE_HEXADECIMAL_NAMES.contains(valueStr.toUpperCase())) {
            return STRING_OUTPUT_TYPE_HEXADECIMAL;
        }
        return STRING_OUTPUT_TYPE_BASE64;
    }

    
    public static String toHexadecimal(final byte[] message) {
        if (message == null) {
            return null;
        }
        final StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < message.length; i++) {
            int curByte = message[i] & 0xff;
            buffer.append(hexDigits[(curByte >> 4)]);
            buffer.append(hexDigits[curByte & 0xf]);
        }
        return buffer.toString();
    }
    
    
    public static byte[] fromHexadecimal(final String message) {
        if (message == null) {
            return null;
        }
        if ((message.length() % 2) != 0) {
            throw new EncryptionOperationNotPossibleException();
        }
        try {
            final byte[] result = new byte[message.length() / 2];
            for (int i = 0; i < message.length(); i = i + 2) {
                final int first = Integer.parseInt("" + message.charAt(i), 16);
                final int second = Integer.parseInt("" + message.charAt(i + 1), 16);
                result[i/2] = (byte) (0x0 + ((first & 0xff) << 4) + (second & 0xff));
            }
            return result;
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
    }
    
    
    public static boolean isEmpty(final String string) {
        if (string == null || string.length() == 0) {
            return true;
        }
        return false;
    }

    
    public static boolean isNotEmpty(final String string) {
        if (string == null || string.length() == 0) {
            return false;
        }
        return true;
    }
    
    
    public static void validateNotNull(final Object object, final String message) {
        if (object == null) {
            throw new IllegalArgumentException(message);
        }
    }
    
    
    public static void validateNotEmpty(final String string, final String message) {
        if (isEmpty(string)) {
            throw new IllegalArgumentException(message);
        }
    }
    
    
    public static void validateIsTrue(final boolean expression, final String message) {
        if (expression == false) {
            throw new IllegalArgumentException(message);
        }
    }
    
    
    
    
    public static String[] split(final String string) {
        // Whitespace will be used as separator
        return split(string, null);
    }
    
    
    public static String[] split(final String string, final String separators) {

        if (string == null) {
            return null;
        }
        
        final int length = string.length();
        
        if (length == 0) {
            return new String[0];
        }
        
        final List results = new ArrayList();
        int i = 0;
        int start = 0;
        boolean tokenInProgress = false;
        
        if (separators == null) {
            
            while (i < length) {
                if (Character.isWhitespace(string.charAt(i))) {
                    if (tokenInProgress) {
                        results.add(string.substring(start, i));
                        tokenInProgress = false;
                    }
                    start = ++i;
                    continue;
                }
                tokenInProgress = true;
                i++;
            }
            
        } else if (separators.length() == 1) {
            
            final char separator = separators.charAt(0);
            while (i < length) {
                if (string.charAt(i) == separator) {
                    if (tokenInProgress) {
                        results.add(string.substring(start, i));
                        tokenInProgress = false;
                    }
                    start = ++i;
                    continue;
                }
                tokenInProgress = true;
                i++;
            }
            
        } else {
            
            while (i < length) {
                if (separators.indexOf(string.charAt(i)) >= 0) {
                    if (tokenInProgress) {
                        results.add(string.substring(start, i));
                        tokenInProgress = false;
                    }
                    start = ++i;
                    continue;
                }
                tokenInProgress = true;
                i++;
            }
            
        }
        
        if (tokenInProgress) {
            results.add(string.substring(start, i));
        }
        
        return (String[]) results.toArray(new String[results.size()]);
        
    }
    
    
    
    
    public static String substringBefore(final String string, final String separator) {
        
        if (isEmpty(string) || separator == null) {
            return string;
        }
        if (separator.length() == 0) {
            return "";
        }
        final int pos = string.indexOf(separator);
        if (pos == -1) {
            return string;
        }
        return string.substring(0, pos);
        
    }
    
    
    
    public static String substringAfter(final String string, final String separator) {
        if (isEmpty(string)) {
            return string;
        }
        if (separator == null) {
            return "";
        }
        final int pos = string.indexOf(separator);
        if (pos == -1) {
            return "";
        }
        return string.substring(pos + separator.length());
    }
    
    
    
    public static int nextRandomInt() {
        return (int)(Math.random() * Integer.MAX_VALUE);
    }
    
    
    
    public static byte[] appendArrays(final byte[] firstArray, final byte[] secondArray) {
    
        validateNotNull(firstArray, "Appended array cannot be null");
        validateNotNull(secondArray, "Appended array cannot be null");
        
        final byte[] result = new byte[firstArray.length + secondArray.length];
        
        System.arraycopy(firstArray, 0, result, 0, firstArray.length);
        System.arraycopy(secondArray, 0, result, firstArray.length, secondArray.length);
        
        return result;
        
    }
    
    
    // This class should only be called statically
    private CommonUtils() {
        super();
    }
    
}
