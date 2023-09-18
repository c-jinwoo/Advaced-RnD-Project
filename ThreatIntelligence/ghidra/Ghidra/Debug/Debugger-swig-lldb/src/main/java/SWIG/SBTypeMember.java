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

public class SBTypeMember {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBTypeMember(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBTypeMember obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBTypeMember(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBTypeMember() {
    this(lldbJNI.new_SBTypeMember__SWIG_0(), true);
  }

  public SBTypeMember(SBTypeMember rhs) {
    this(lldbJNI.new_SBTypeMember__SWIG_1(SBTypeMember.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBTypeMember_IsValid(swigCPtr, this);
  }

  public String GetName() {
    return lldbJNI.SBTypeMember_GetName(swigCPtr, this);
  }

  public SBType GetType() {
    return new SBType(lldbJNI.SBTypeMember_GetType(swigCPtr, this), true);
  }

  public java.math.BigInteger GetOffsetInBytes() {
    return lldbJNI.SBTypeMember_GetOffsetInBytes(swigCPtr, this);
  }

  public java.math.BigInteger GetOffsetInBits() {
    return lldbJNI.SBTypeMember_GetOffsetInBits(swigCPtr, this);
  }

  public boolean IsBitfield() {
    return lldbJNI.SBTypeMember_IsBitfield(swigCPtr, this);
  }

  public long GetBitfieldSizeInBits() {
    return lldbJNI.SBTypeMember_GetBitfieldSizeInBits(swigCPtr, this);
  }

  public String __str__() {
    return lldbJNI.SBTypeMember___str__(swigCPtr, this);
  }

}
