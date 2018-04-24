package org.bouncycastle.jcajce.spec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.spec.AlgorithmParameterSpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * Parameters for the Skein hash function - a series of byte[] strings identified by integer tags.
 * <p>
 * Parameterised Skein can be used for:
 * <ul>
 * <li>MAC generation, by providing a {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setKey(byte[]) key}.</li>
 * <li>Randomised hashing, by providing a {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setNonce(byte[]) nonce}.</li>
 * <li>A hash function for digital signatures, associating a
 * {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setPublicKey(byte[]) public key} with the message digest.</li>
 * <li>A key derivation function, by providing a
 * {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setKeyIdentifier(byte[]) key identifier}.</li>
 * <li>Personalised hashing, by providing a
 * {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setPersonalisation(java.util.Date, String, String) recommended format} or
 * {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec.Builder#setPersonalisation(byte[]) arbitrary} personalisation string.</li>
 * </ul>
 *
 * @see org.bouncycastle.crypto.digests.SkeinEngine
 * @see org.bouncycastle.crypto.digests.SkeinDigest
 * @see org.bouncycastle.crypto.macs.SkeinMac
 */
public class SkeinParameterSpec
    implements AlgorithmParameterSpec
{
    /**
     * The parameter type for a secret key, supporting MAC or KDF functions: {@value
     * #PARAM_TYPE_KEY}.
     */
    public static final int PARAM_TYPE_KEY = 0;

    /**
     * The parameter type for the Skein configuration block: {@value #PARAM_TYPE_CONFIG}.
     */
    public static final int PARAM_TYPE_CONFIG = 4;

    /**
     * The parameter type for a personalisation string: {@value #PARAM_TYPE_PERSONALISATION}.
     */
    public static final int PARAM_TYPE_PERSONALISATION = 8;

    /**
     * The parameter type for a public key: {@value #PARAM_TYPE_PUBLIC_KEY}.
     */
    public static final int PARAM_TYPE_PUBLIC_KEY = 12;

    /**
     * The parameter type for a key identifier string: {@value #PARAM_TYPE_KEY_IDENTIFIER}.
     */
    public static final int PARAM_TYPE_KEY_IDENTIFIER = 16;

    /**
     * The parameter type for a nonce: {@value #PARAM_TYPE_NONCE}.
     */
    public static final int PARAM_TYPE_NONCE = 20;

    /**
     * The parameter type for the message: {@value #PARAM_TYPE_MESSAGE}.
     */
    public static final int PARAM_TYPE_MESSAGE = 48;

    /**
     * The parameter type for the output transformation: {@value #PARAM_TYPE_OUTPUT}.
     */
    public static final int PARAM_TYPE_OUTPUT = 63;

    private Map parameters;

    public SkeinParameterSpec()
    {
        this(new HashMap());
    }

    private SkeinParameterSpec(Map parameters)
    {
        this.parameters = Collections.unmodifiableMap(parameters);
    }

    /**
     * Obtains a map of type (Integer) to value (byte[]) for the parameters tracked in this object.
     */
    public Map getParameters()
    {
        return parameters;
    }

    /**
     * Obtains the value of the {@link #PARAM_TYPE_KEY key parameter}, or <code>null</code> if not
     * set.
     */
    public byte[] getKey()
    {
        return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_KEY)));
    }

    /**
     * Obtains the value of the {@link #PARAM_TYPE_PERSONALISATION personalisation parameter}, or
     * <code>null</code> if not set.
     */
    public byte[] getPersonalisation()
    {
        return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_PERSONALISATION)));
    }

    /**
     * Obtains the value of the {@link #PARAM_TYPE_PUBLIC_KEY public key parameter}, or
     * <code>null</code> if not set.
     */
    public byte[] getPublicKey()
    {
        return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_PUBLIC_KEY)));
    }

    /**
     * Obtains the value of the {@link #PARAM_TYPE_KEY_IDENTIFIER key identifier parameter}, or
     * <code>null</code> if not set.
     */
    public byte[] getKeyIdentifier()
    {
        return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_KEY_IDENTIFIER)));
    }

    /**
     * Obtains the value of the {@link #PARAM_TYPE_NONCE nonce parameter}, or <code>null</code> if
     * not set.
     */
    public byte[] getNonce()
    {
        return Arrays.clone((byte[])parameters.get(Integers.valueOf(PARAM_TYPE_NONCE)));
    }

    /**
     * A builder for {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec}.
     */
    public static class Builder
    {
        private Map parameters = new HashMap();

        public Builder()
        {
        }

        public Builder(SkeinParameterSpec params)
        {
            Iterator keys = params.parameters.keySet().iterator();
            while (keys.hasNext())
            {
                Integer key = (Integer)keys.next();
                parameters.put(key, params.parameters.get(key));
            }
        }

        /**
         * Sets a parameters to apply to the Skein hash function.<br>
         * Parameter types must be in the range 0,5..62, and cannot use the value {@value
         * org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_MESSAGE} (reserved for message body).
         * <p>
         * Parameters with type &lt; {@value org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_MESSAGE} are processed before
         * the message content, parameters with type &gt; {@value org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_MESSAGE}
         * are processed after the message and prior to output.
         * </p>
         *
         * @param type  the type of the parameter, in the range 5..62.
         * @param value the byte sequence of the parameter.
         * @return the current builder instance.
         */
        public Builder set(int type, byte[] value)
        {
            if (value == null)
            {
                throw new IllegalArgumentException("Parameter value must not be null.");
            }
            if ((type != PARAM_TYPE_KEY)
                && (type <= PARAM_TYPE_CONFIG || type >= PARAM_TYPE_OUTPUT || type == PARAM_TYPE_MESSAGE))
            {
                throw new IllegalArgumentException("Parameter types must be in the range 0,5..47,49..62.");
            }
            if (type == PARAM_TYPE_CONFIG)
            {
                throw new IllegalArgumentException("Parameter type " + PARAM_TYPE_CONFIG
                    + " is reserved for internal use.");
            }
            this.parameters.put(Integers.valueOf(type), value);
            return this;
        }

        /**
         * Sets the {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_KEY} parameter.
         */
        public Builder setKey(byte[] key)
        {
            return set(PARAM_TYPE_KEY, key);
        }

        /**
         * Sets the {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_PERSONALISATION} parameter.
         */
        public Builder setPersonalisation(byte[] personalisation)
        {
            return set(PARAM_TYPE_PERSONALISATION, personalisation);
        }

        /**
         * Implements the recommended personalisation format for Skein defined in Section 4.11 of
         * the Skein 1.3 specification.
         * <p>
         * The format is <code>YYYYMMDD email@address distinguisher</code>, encoded to a byte
         * sequence using UTF-8 encoding.
         * </p>
         *
         * @param date          the date the personalised application of the Skein was defined.
         * @param emailAddress  the email address of the creation of the personalised application.
         * @param distinguisher an arbitrary personalisation string distinguishing the application.
         * @return the current builder instance.
         */
        public Builder setPersonalisation(Date date, String emailAddress, String distinguisher)
        {
            try
            {
                final ByteArrayOutputStream bout = new ByteArrayOutputStream();
                final OutputStreamWriter out = new OutputStreamWriter(bout, "UTF-8");
                final DateFormat format = new SimpleDateFormat("YYYYMMDD");
                out.write(format.format(date));
                out.write(" ");
                out.write(emailAddress);
                out.write(" ");
                out.write(distinguisher);
                out.close();
                return set(PARAM_TYPE_PERSONALISATION, bout.toByteArray());
            }
            catch (IOException e)
            {
                throw new IllegalStateException("Byte I/O failed: " + e);
            }
        }

        /**
         * Implements the recommended personalisation format for Skein defined in Section 4.11 of
         * the Skein 1.3 specification. You may need to use this method if the default locale
         * doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible implementations.
         * <p>
         * The format is <code>YYYYMMDD email@address distinguisher</code>, encoded to a byte
         * sequence using UTF-8 encoding.
         *
         * @param date          the date the personalised application of the Skein was defined.
         * @param dateLocale    locale to be used for date interpretation.
         * @param emailAddress  the email address of the creation of the personalised application.
         * @param distinguisher an arbitrary personalisation string distinguishing the application.
         * @return the current builder instance.
         */
        public Builder setPersonalisation(Date date, Locale dateLocale, String emailAddress, String distinguisher)
        {
            try
            {
                final ByteArrayOutputStream bout = new ByteArrayOutputStream();
                final OutputStreamWriter out = new OutputStreamWriter(bout, "UTF-8");
                final DateFormat format = new SimpleDateFormat("YYYYMMDD", dateLocale);
                out.write(format.format(date));
                out.write(" ");
                out.write(emailAddress);
                out.write(" ");
                out.write(distinguisher);
                out.close();
                return set(PARAM_TYPE_PERSONALISATION, bout.toByteArray());
            }
            catch (IOException e)
            {
                throw new IllegalStateException("Byte I/O failed: " + e);
            }
        }

        /**
         * Sets the {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_KEY_IDENTIFIER} parameter.
         *
         * @return the current builder instance.
         */
        public Builder setPublicKey(byte[] publicKey)
        {
            return set(PARAM_TYPE_PUBLIC_KEY, publicKey);
        }

        /**
         * Sets the {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_KEY_IDENTIFIER} parameter.
         *
         * @return the current builder instance.
         */
        public Builder setKeyIdentifier(byte[] keyIdentifier)
        {
            return set(PARAM_TYPE_KEY_IDENTIFIER, keyIdentifier);
        }

        /**
         * Sets the {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec#PARAM_TYPE_NONCE} parameter.
         *
         * @return the current builder instance.
         */
        public Builder setNonce(byte[] nonce)
        {
            return set(PARAM_TYPE_NONCE, nonce);
        }

        /**
         * Constructs a new {@link org.bouncycastle.jcajce.spec.SkeinParameterSpec} instance with the parameters provided to this
         * builder.
         */
        public SkeinParameterSpec build()
        {
            return new SkeinParameterSpec(parameters);
        }
    }
}
