/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public final class InputReaderAction {
  public final static InputReaderAction eInputReaderActivate = new InputReaderAction("eInputReaderActivate");
  public final static InputReaderAction eInputReaderAsynchronousOutputWritten = new InputReaderAction("eInputReaderAsynchronousOutputWritten");
  public final static InputReaderAction eInputReaderReactivate = new InputReaderAction("eInputReaderReactivate");
  public final static InputReaderAction eInputReaderDeactivate = new InputReaderAction("eInputReaderDeactivate");
  public final static InputReaderAction eInputReaderGotToken = new InputReaderAction("eInputReaderGotToken");
  public final static InputReaderAction eInputReaderInterrupt = new InputReaderAction("eInputReaderInterrupt");
  public final static InputReaderAction eInputReaderEndOfFile = new InputReaderAction("eInputReaderEndOfFile");
  public final static InputReaderAction eInputReaderDone = new InputReaderAction("eInputReaderDone");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static InputReaderAction swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + InputReaderAction.class + " with value " + swigValue);
  }

  private InputReaderAction(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private InputReaderAction(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private InputReaderAction(String swigName, InputReaderAction swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static InputReaderAction[] swigValues = { eInputReaderActivate, eInputReaderAsynchronousOutputWritten, eInputReaderReactivate, eInputReaderDeactivate, eInputReaderGotToken, eInputReaderInterrupt, eInputReaderEndOfFile, eInputReaderDone };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

