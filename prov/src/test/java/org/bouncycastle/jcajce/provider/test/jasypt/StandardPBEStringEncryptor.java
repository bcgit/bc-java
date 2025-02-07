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

import java.security.Provider;



/**
 * <p>
 * Standard implementation of the {@link PBEStringEncryptor} interface.
 * This class lets the user specify the algorithm (and provider) to be used for 
 * encryption, the password to use,
 * the number of hashing iterations and the salt generator
 * that will be applied for obtaining
 * the encryption key.
 * </p>
 * <p>
 * This class avoids byte-conversion problems related to the fact of 
 * different platforms having different default charsets, and returns 
 * encryption results in the form of BASE64-encoded or HEXADECIMAL 
 * ASCII Strings.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * <p>
 * <br/><b><u>Configuration</u></b>
 * </p>
 * <p>
 * The algorithm, provider, password, key-obtention iterations and salt generator can take 
 * values in any of these ways:
 * <ul>
 *   <li>Using its default values (except for password).</li>
 *   <li>Setting a <tt>{@link PBEConfig}</tt> 
 *       object which provides new 
 *       configuration values.</li>
 *   <li>Calling the corresponding <tt>setX(...)</tt> methods.</li>
 * </ul>
 * And the actual values to be used for initialization will be established
 * by applying the following priorities:
 * <ol>
 *   <li>First, the default values are considered (except for password).</li>
 *   <li>Then, if a <tt>{@link PBEConfig}</tt> 
 *       object has been set with
 *       <tt>setConfig(...)</tt>, the non-null values returned by its
 *       <tt>getX()</tt> methods override the default values.</li>
 *   <li>Finally, if the corresponding <tt>setX(...)</tt> method has been called
 *       on the encryptor itself for any of the configuration parameters, the 
 *       values set by these calls override all of the above.</li>
 * </ol>
 * </p>
 * 
 * <p>
 * <br/><b><u>Initialization</u></b>
 * </p>
 * <p>
 * Before it is ready to encrypt, an object of this class has to be
 * <i>initialized</i>. Initialization happens:
 * <ul>
 *   <li>When <tt>initialize()</tt> is called.</li>
 *   <li>When <tt>encrypt(...)</tt> or <tt>decrypt(...)</tt> are called for the
 *       first time, if <tt>initialize()</tt> has not been called before.</li>
 * </ul>
 * Once an encryptor has been initialized, trying to
 * change its configuration will
 * result in an <tt>AlreadyInitializedException</tt> being thrown.
 * </p>
 * 
 * <p>
 * <br/><b><u>Usage</u></b>
 * </p>
 * <p>
 * An encryptor may be used for:
 * <ul>
 *   <li><i>Encrypting messages</i>, by calling the <tt>encrypt(...)</tt> method.</li>
 *   <li><i>Decrypting messages</i>, by calling the <tt>decrypt(...)</tt> method.</li> 
 * </ul>
 * <b>If a random salt generator is used, two encryption results for 
 * the same message will always be different
 * (except in the case of random salt coincidence)</b>. This may enforce
 * security by difficulting brute force attacks on sets of data at a time
 * and forcing attackers to perform a brute force attack on each separate
 * piece of encrypted data.
 * </p>
 * <p>     
 * To learn more about the mechanisms involved in encryption, read
 * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
 * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class StandardPBEStringEncryptor
    implements PBEStringCleanablePasswordEncryptor {

    /**
     * <p>
     * Charset to be used to obtain "encryptable" byte arrays from input 
     * Strings. <b>Set to UTF-8</b>.
     * </p>
     * <p> 
     * This charset has to be fixed to some value so that we avoid problems 
     * with different platforms having different "default" charsets. 
     * </p>
     * <p>
     * It is set to <b>UTF-8</b> because it covers the whole spectrum of 
     * characters representable in Java (which internally uses UTF-16), and 
     * avoids the size penalty of UTF-16 (which will always use two bytes for
     * representing each character, even if it is an ASCII one).
     * </p>
     * <p>
     * Setting it to UTF-8 does not mean that Strings that originally come,
     * for example, from an ISO-8859-1 input, won't be correctly encoded, as we 
     * only need to use the same charset both when encoding and decoding. That
     * way the same String will be reconstructed independently of the original
     * encoding (for encrypting, we only need "a byte representation" of the 
     * string, not "a readable byte representation").
     * </p>
     */
    private static final String MESSAGE_CHARSET = "UTF-8";
    
    /**
     * <p>
     * Charset to be used for encoding the encryption results. 
     * Set to <b>US-ASCII</b>.
     * </p>
     * <p>
     * The result of encrypting some bytes can be any other bytes, and so
     * the result of encrypting, for example, some LATIN-1 valid String bytes, 
     * can be bytes that may not conform a "valid" LATIN-1 String.
     * </p>
     * <p>
     * Because of this, encryption results are always encoded in <i>BASE64</i>
     * (default) or <i>HEXADECIMAL</i> after being created, and this ensures 
     * that the results will make perfectly representable, safe ASCII Strings. 
     * Because of this, the charset used to convert the encrypted bytes to the
     * returned String is set to <b>US-ASCII</b>.
     * </p>
     */
    private static final String ENCRYPTED_MESSAGE_CHARSET = "US-ASCII";


    /**
     * <p>
     * Default type of String output. Set to <b>BASE64</b>. 
     * </p> 
     */
    public static final String DEFAULT_STRING_OUTPUT_TYPE = 
        CommonUtils.STRING_OUTPUT_TYPE_BASE64;
    

    // If the config object set is a StringPBEConfig, it must be referenced
    private StringPBEConfig stringPBEConfig = null;
    
    // This variable holds the type of String output which will be done,
    // and also a boolean variable for faster comparison
    private String stringOutputType = DEFAULT_STRING_OUTPUT_TYPE;
    private boolean stringOutputTypeBase64 = true;

    
    /*
     * Set of booleans which indicate whether the config or default values
     * have to be overriden because of the setX methods having been
     * called.
     */
    private boolean stringOutputTypeSet = false;
    
    
    // The StandardPBEByteEncryptor that will be internally used.
    private final StandardPBEByteEncryptor byteEncryptor;
    
    // BASE64 encoder which will make sure the returned results are
    // valid US-ASCII strings.
    // The Base64 encoder is THREAD-SAFE
    private final Base64 base64;

    
    
    /**
     * Creates a new instance of <tt>StandardPBEStringEncryptor</tt>.
     */
    public StandardPBEStringEncryptor() {
        super();
        this.byteEncryptor = new StandardPBEByteEncryptor();
        this.base64 = new Base64();
    }


    
    /*
     * Creates a new instance of <tt>StandardPBEStringEncryptor</tt> using
     * the specified byte encryptor (constructor used for cloning)
     */
    private StandardPBEStringEncryptor(final StandardPBEByteEncryptor standardPBEByteEncryptor) {
        super();
        this.byteEncryptor = standardPBEByteEncryptor;
        this.base64 = new Base64();
    }

    
    
    /**
     * <p>
     * Sets a <tt>{@link PBEConfig}</tt> object 
     * for the encryptor. If this config
     * object is set, it will be asked values for:
     * </p>
     * 
     * <ul>
     *   <li>Algorithm</li>
     *   <li>Security Provider (or provider name)</li>
     *   <li>Password</li>
     *   <li>Hashing iterations for obtaining the encryption key</li>
     *   <li>Salt generator</li>
     *   <li>Output type (base64, hexadecimal) 
     *       (only <tt>StringPBEConfig</tt>)</li>
     * </ul>
     * 
     * <p>
     * The non-null values it returns will override the default ones, 
     * <i>and will be overriden by any values specified with a <tt>setX</tt>
     * method</i>.
     * </p>
     * 
     * @param config the <tt>PBEConfig</tt> object to be used as the 
     *               source for configuration parameters.
     */
    public synchronized void setConfig(final PBEConfig config) {
        this.byteEncryptor.setConfig(config);
        if ((config != null) && (config instanceof StringPBEConfig)) {
            this.stringPBEConfig = (StringPBEConfig) config;
        }
    }

    
    /**
     * <p>
     * Sets the algorithm to be used for encryption, like 
     * <tt>PBEWithMD5AndDES</tt>.
     * </p>
     * <p>
     * This algorithm has to be supported by your JCE provider (if you specify
     * one, or the default JVM provider if you don't) and, if it is supported,
     * you can also specify <i>mode</i> and <i>padding</i> for 
     * it, like <tt>ALGORITHM/MODE/PADDING</tt>.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used.
     */
    public void setAlgorithm(final String algorithm) {
        this.byteEncryptor.setAlgorithm(algorithm);
    }

    
    /**
     * <p>
     * Sets the password to be used.
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting
     * this parameter either from a 
     * {@link PBEConfig} object or from
     * a call to <tt>setPassword</tt> will result in an
     * EncryptionInitializationException being thrown during initialization.
     * </p>
     * 
     * @param password the password to be used.
     */
    public void setPassword(final String password) {
        this.byteEncryptor.setPassword(password);
    }
    
    
    /**
     * <p>
     * Sets the password to be used, as a char[].
     * </p>
     * <p>
     * This allows the password to be specified as a <i>cleanable</i>
     * char[] instead of a String, in extreme security conscious environments
     * in which no copy of the password as an immutable String should
     * be kept in memory.
     * </p>
     * <p>
     * <b>Important</b>: the array specified as a parameter WILL BE COPIED
     * in order to be stored as encryptor configuration. The caller of
     * this method will therefore be responsible for its cleaning (jasypt
     * will only clean the internally stored copy).
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting
     * this parameter either from a 
     * {@link PBEConfig} object or from
     * a call to <tt>setPassword</tt> will result in an
     * EncryptionInitializationException being thrown during initialization.
     * </p>
     * 
     * @since 1.8
     * 
     * @param password the password to be used.
     */
    public void setPasswordCharArray(char[] password) {
        this.byteEncryptor.setPasswordCharArray(password);
    }
    

    /**
     * <p>
     * Set the number of hashing iterations applied to obtain the
     * encryption key.
     * </p>
     * <p>
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * @param keyObtentionIterations the number of iterations
     */
    public void setKeyObtentionIterations(final int keyObtentionIterations) {
        this.byteEncryptor.setKeyObtentionIterations(keyObtentionIterations);
    }

    
    /**
     * <p>
     * Sets the salt generator to be used. If no salt generator is specified,
     * an instance of {@link org.jasypt.salt.RandomSaltGenerator} will be used. 
     * </p>
     * 
     * @param saltGenerator the salt generator to be used.
     */
    public void setSaltGenerator(final SaltGenerator saltGenerator) {
        this.byteEncryptor.setSaltGenerator(saltGenerator);
    }

    /**
     * <p>
     * Sets the IV generator to be used. If no IV generator is specified,
     * an instance of {@link org.jasypt.iv.NoIvGenerator} will be used.
     * </p>
     *
     * @param ivGenerator the IV generator to be used.
     */
    public void setIvGenerator(final IvGenerator ivGenerator) {
        this.byteEncryptor.setIvGenerator(ivGenerator);
    }
    
    
    /**
     * <p>
     * Sets the name of the security provider to be asked for the
     * encryption algorithm. This security provider has to be registered 
     * beforehand at the JVM security framework. 
     * </p>
     * <p>
     * The provider can also be set with the {@link #setProvider(Provider)}
     * method, in which case it will not be necessary neither registering
     * the provider beforehand,
     * nor calling this {@link #setProviderName(String)} method to specify
     * a provider name.
     * </p>
     * <p>
     * Note that a call to {@link #setProvider(Provider)} overrides any value 
     * set by this method.
     * </p>
     * <p>
     * If no provider name / provider is explicitly set, the default JVM
     * provider will be used.
     * </p>
     * 
     * @since 1.3
     * 
     * @param providerName the name of the security provider to be asked
     *                     for the encryption algorithm.
     */
    public void setProviderName(final String providerName) {
        this.byteEncryptor.setProviderName(providerName);
    }
    
    
    /**
     * <p>
     * Sets the security provider to be asked for the encryption algorithm.
     * The provider does not have to be registered at the security 
     * infrastructure beforehand, and its being used here will not result in
     * its being registered.
     * </p>
     * <p>
     * If this method is called, calling {@link #setProviderName(String)}
     * becomes unnecessary.
     * </p>
     * <p>
     * If no provider name / provider is explicitly set, the default JVM
     * provider will be used.
     * </p>
     * 
     * @since 1.3
     * 
     * @param provider the provider to be asked for the chosen algorithm
     */
    public void setProvider(final Provider provider) {
        this.byteEncryptor.setProvider(provider);
    }
    
    
    /**
     * <p>
     * Sets the the form in which String output
     * will be encoded. Available encoding types are:
     * </p>
     * <ul>
     *   <li><tt><b>base64</b></tt> (default)</li>
     *   <li><tt><b>hexadecimal</b></tt></li>
     * </ul>
     * <p>
     * If not set, null will be returned.
     * </p>

     * @since 1.3
     * 
     * @param stringOutputType the string output type.
     */
    public synchronized void setStringOutputType(final String stringOutputType) {
        CommonUtils.validateNotEmpty(stringOutputType, 
                "String output type cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.stringOutputType = 
            CommonUtils.
                getStandardStringOutputType(stringOutputType);

        this.stringOutputTypeSet = true;
    }

    

    


    
    
    
    
    /*
     * Clone this encryptor 'size' times and initialize it.
     * This encryptor will be at position 0 itself.
     * Clones will NOT be initialized.
     */
    synchronized StandardPBEStringEncryptor[] cloneAndInitializeEncryptor(final int size) {
        
        final StandardPBEByteEncryptor[] byteEncryptorClones =
            this.byteEncryptor.cloneAndInitializeEncryptor(size);
        
        initializeSpecifics();

        final StandardPBEStringEncryptor[] clones = new StandardPBEStringEncryptor[size];
        
        clones[0] = this;
        
        for (int i = 1; i < size; i++) {
            clones[i] = new StandardPBEStringEncryptor(byteEncryptorClones[i]);
            if (CommonUtils.isNotEmpty(this.stringOutputType)) {
                clones[i].setStringOutputType(this.stringOutputType);
            }
        }
        
        return clones;
        
    }
    
    
    

    /**
     * <p>
     *   Returns true if the encryptor has already been initialized, false if
     *   not.<br/> 
     *   Initialization happens:
     * </p>
     * <ul>
     *   <li>When <tt>initialize</tt> is called.</li>
     *   <li>When <tt>encrypt</tt> or <tt>decrypt</tt> are called for the
     *       first time, if <tt>initialize</tt> has not been called before.</li>
     * </ul>
     * <p>
     *   Once an encryptor has been initialized, trying to
     *   change its configuration will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @return true if the encryptor has already been initialized, false if
     *         not.
     */
    public boolean isInitialized() {
        return this.byteEncryptor.isInitialized();
    }

    
    /**
     * <p>
     * Initialize the encryptor.
     * </p>
     * <p>
     * This operation will consist in determining the actual configuration 
     * values to be used, and then initializing the encryptor with them.
     * <br/>
     * These values are decided by applying the following priorities:
     * </p>
     * <ol>
     *   <li>First, the default values are considered (except for password).
     *   </li>
     *   <li>Then, if a 
     *       <tt>{@link PBEConfig}</tt> 
     *       object has been set with
     *       <tt>setConfig</tt>, the non-null values returned by its
     *       <tt>getX</tt> methods override the default values.</li>
     *   <li>Finally, if the corresponding <tt>setX</tt> method has been called
     *       on the encryptor itself for any of the configuration parameters, 
     *       the values set by these calls override all of the above.</li>
     * </ol>
     * <p>
     *   Once an encryptor has been initialized, trying to
     *   change its configuration will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public synchronized void initialize() {
        
        // Double-check to avoid synchronization issues
        if (!this.isInitialized()) {
            initializeSpecifics();
            this.byteEncryptor.initialize();
        }

    }
    
    
    
    
    private void initializeSpecifics() {
        /*
         * If a StringPBEConfig object has been set, we need to 
         * consider the values it returns (if, for each value, the
         * corresponding "setX" method has not been called).
         */
        if (this.stringPBEConfig != null) {
            
            final String configStringOutputType = 
                this.stringPBEConfig.getStringOutputType();

            this.stringOutputType = 
                ((this.stringOutputTypeSet) || (configStringOutputType == null))?
                        this.stringOutputType : configStringOutputType;
            
        }
        
        this.stringOutputTypeBase64 =
            (CommonUtils.STRING_OUTPUT_TYPE_BASE64.
                equalsIgnoreCase(this.stringOutputType));

    }
    
    
    /**
     * <p>
     * Encrypts a message using the specified configuration.
     * </p>
     * </p>
     * The Strings returned by this method are BASE64-encoded (default) or
     * HEXADECIMAL ASCII Strings.
     * </p>
     * <p>
     * The mechanisms applied to perform the encryption operation are described
     * in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * This encryptor uses a salt for each encryption
     * operation. The size of the salt depends on the algorithm
     * being used. This salt is used
     * for creating the encryption key and, if generated by a random generator,
     * it is also appended unencrypted at the beginning
     * of the results so that a decryption operation can be performed.
     * </p>
     * <p>
     * <b>If a random salt generator is used, two encryption results for 
     * the same message will always be different
     * (except in the case of random salt coincidence)</b>. This may enforce
     * security by difficulting brute force attacks on sets of data at a time
     * and forcing attackers to perform a brute force attack on each separate
     * piece of encrypted data.
     * </p>
     * 
     * @param message the String message to be encrypted
     * @return the result of encryption 
     * @throws EncryptionOperationNotPossibleException if the encryption 
     *         operation fails, ommitting any further information about the
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public String encrypt(final String message) {
        
        if (message == null) {
            return null;
        }

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        try {

            // The input String is converted into bytes using MESSAGE_CHARSET
            // as a fixed charset to avoid problems with different platforms
            // having different default charsets (see MESSAGE_CHARSET doc).
            final byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            
            // The StandardPBEByteEncryptor does its job.
            byte[] encryptedMessage = this.byteEncryptor.encrypt(messageBytes);
            
            // We encode the result in BASE64 or HEXADECIMAL so that we obtain
            // the safest result String possible.
            String result = null;
            if (this.stringOutputTypeBase64) {
                encryptedMessage = this.base64.encode(encryptedMessage);
                result = new String(encryptedMessage,ENCRYPTED_MESSAGE_CHARSET);
            } else {
                result = CommonUtils.toHexadecimal(encryptedMessage);
            }
            
            return result;
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (EncryptionOperationNotPossibleException e) {
            throw e;
        } catch (Exception e) {
            // If encryption fails, it is more secure not to return any 
            // information about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    /**
     * <p>
     * Decrypts a message using the specified configuration.
     * </p>
     * <p>
     * This method expects to receive a BASE64-encoded (default)
     * or HEXADECIMAL ASCII String.
     * </p>
     * <p>
     * The mechanisms applied to perform the decryption operation are described
     * in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * If a random salt generator is used, this decryption operation will
     * expect to find an unencrypted salt at the 
     * beginning of the encrypted input, so that the decryption operation can be
     * correctly performed (there is no other way of knowing it).
     * </p>
     * 
     * @param encryptedMessage the String message to be decrypted
     * @return the result of decryption 
     * @throws EncryptionOperationNotPossibleException if the decryption 
     *         operation fails, ommitting any further information about the
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public String decrypt(final String encryptedMessage) {
        
        if (encryptedMessage == null) {
            return null;
        }

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        try {
            
            byte[] encryptedMessageBytes = null;

            // Decode input to bytes depending on whether it is a
            // BASE64-encoded or hexadecimal String
            if (this.stringOutputTypeBase64) {
                encryptedMessageBytes = 
                    encryptedMessage.getBytes(ENCRYPTED_MESSAGE_CHARSET);
                encryptedMessageBytes = 
                    this.base64.decode(encryptedMessageBytes);
            } else {
                encryptedMessageBytes = 
                    CommonUtils.fromHexadecimal(encryptedMessage);
            }

            // Let the byte encyptor decrypt
            final byte[] message = this.byteEncryptor.decrypt(encryptedMessageBytes);
            
            // Return the resulting decrypted String, using MESSAGE_CHARSET
            // as charset to maintain between encryption and decyption
            // processes.
            return new String(message, MESSAGE_CHARSET);
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (EncryptionOperationNotPossibleException e) {
            throw e;
        } catch (Exception e) {
            // If decryption fails, it is more secure not to return any 
            // information about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }

    }

    
}
