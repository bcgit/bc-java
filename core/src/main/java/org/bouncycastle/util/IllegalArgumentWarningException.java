package org.bouncycastle.util;

import java.util.Collections;
import java.util.List;

public class IllegalArgumentWarningException extends IllegalArgumentException {
  
  private static final long serialVersionUID = 5735291408274180892L;
  List<String> messages;
  Object object;
  
  public IllegalArgumentWarningException(List<String> messages, Object object, Throwable cause) {
    super(messages.get(0), cause);
    this.messages = messages;
    this.object = object;
  }

  public IllegalArgumentWarningException(List<String> messages, Object object) {
    this(messages, object, null);
  }

  public IllegalArgumentWarningException(String message, Object object) {
    this(Collections.singletonList(message), object, null);
  }

  public IllegalArgumentWarningException(Object object, Throwable cause) {
    this(Collections.singletonList(cause.getMessage()), object, cause);
  }

  public List<String> getMessages() {
    return messages;
  }

  public <T> T getObject(Class<T> clazz) {
    if (clazz.isInstance(object)) {
      return (T) object;
    }
    throw new IllegalArgumentException(messages.get(0), this);
  }

}
