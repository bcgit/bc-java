package org.bouncycastle.util;

import java.util.Collections;
import java.util.List;

/**
 * Exception which is thrown when parsing a certificate when errors in the 
 * parsing are detected. This provides a list of the errors that were
 * detected along with the (mostly) parsed object.
 */
public class IllegalArgumentWarningException extends IllegalArgumentException {

    private static final long serialVersionUID = 5735291408274180892L;
    List<String>   messages;
    Object         object;

    /**
     * Basic constructor.
     *
     * @param messages Non empty list of messages to associate with this Exception.
     * @param object The partially parsed object.
     * @param cause The underlying exception (if any).
     */
    public IllegalArgumentWarningException(List<String> messages, Object object, Throwable cause) {
        super(messages.get(0), cause);
        this.messages = messages;
        this.object = object;
    }

    /**
     * Basic constructor.
     *
     * @param messages Non empty list of messages to associate with this Exception.
     * @param object The partially parsed object.
     */
    public IllegalArgumentWarningException(List<String> messages, Object object) {
        this(messages, object, null);
    }

    /**
     * Basic constructor.
     *
     * @param message Single message to be associated with this Exception.
     * @param object The partially parsed object.
     */
    public IllegalArgumentWarningException(String message, Object object) {
        this(Collections.singletonList(message), object, null);
    }

    /**
     * Basic constructor.
     *
     * @param object The partially parsed object.
     * @param cause The underlying exception.
     */
    public IllegalArgumentWarningException(Object object, Throwable cause) {
        this(Collections.singletonList(cause.getMessage()), object, cause);
    }

    /**
     * Gets the list of error messages.
     */
    public List<String> getMessages() {
        return messages;
    }

    /**
     * This gets the partially parsed object -- but only if you provide the correct
     * class!
     *
     * @param clazz The class of the object that you are expecting.
     */
    public <T> T getObject(Class<T> clazz) {
        if (clazz.isInstance(object)) {
            return (T) object;
        }
        throw new IllegalArgumentException(messages.get(0), this);
    }
}
