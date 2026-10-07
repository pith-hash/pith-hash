//! The JNI surface of `pith-hash`: the entry points the Java SDK
//! (`sdk/java`) bind through after `System.load`ing this cdylib.
//!
//! The names follow the JVM's resolve convention for
//! `package hash.pith` + `class PithHash`: `Java_hash_pith_PithHash_<method>`.
//! The existing C ABI in [`crate::ffi`] is untouched — this module only
//! adds `Java_*` symbols and routes through the same safe cores.
//!
//! # The JNIEnv function table
//!
//! Every JNI call goes through the table `env` points at. The suite
//! carries no third-party crates, so the needed prefix of
//! `struct JNINativeInterface_` is declared here: every slot is one
//! pointer wide, unused runs ride as opaque gap arrays, and the slot
//! indices are the JNI standard order verified against OpenJDK's
//! `include/jni.h` (FindClass = 6, Throw = 13, ThrowNew = 14,
//! NewObjectA = 30, GetMethodID = 33, NewStringUTF = 167,
//! GetArrayLength = 171, NewByteArray = 176, NewIntArray = 179,
//! NewLongArray = 180, GetByteArrayRegion = 200,
//! SetByteArrayRegion = 208, SetIntArrayRegion = 211,
//! SetLongArrayRegion = 212). [`new_object_a`] is used — not the
//! varargs `NewObject` — so no call site depends on a varargs ABI.
//!
//! # Error convention
//!
//! Refusals never unwind into the JVM: the export throws
//! `hash.pith.PithFfiException(status, message)` (status codes as in
//! [`crate::ffi`]: `-1` invalid argument, `-2` core refusal) and
//! returns a Java `null`; if the exception class cannot be resolved,
//! a plain `java.lang.RuntimeException` is thrown via `ThrowNew`.

#![allow(unsafe_code)]

use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};

use crate::ffi::{PITH_E_INVALID, PITH_E_REJECTED, describe_bytes, match_slots, signature_bytes};

/// An opaque JVM object handle (`jobject` and friends in `jni.h`).
#[repr(C)]
pub struct JObject {
    _opaque: [u8; 0],
}

/// `jobject`.
pub type Jobject = *mut JObject;
/// `jclass` / `jarray` / `jstring` / `jbyteArray` — all object handles.
pub type JClass = Jobject;
/// See [`JClass`].
pub type Jarray = Jobject;
/// See [`JClass`].
pub type Jstring = Jobject;
/// See [`JClass`].
pub type JbyteArray = Jobject;
/// `jintArray` — an object handle like every other array kind.
pub type JintArray = Jobject;
/// `jlongArray` — an object handle like every other array kind.
pub type JlongArray = Jobject;
/// `jmethodID` — an opaque method handle.
pub type JmethodID = *mut JObject;
/// `jbyte`.
type Jbyte = i8;
/// `jint` / `jsize`.
type Jint = i32;
/// `jlong`.
type Jlong = i64;

/// The `jvalue` argument union (`jni.h`): a slot in `NewObjectA`'s
/// argument vector. Only the two members the exception constructor
/// needs are named.
#[repr(C)]
#[derive(Clone, Copy)]
pub union JValue {
    /// The `jint` view (the exception status).
    pub int_value: Jint,
    /// The object view (the exception message).
    pub object_value: Jobject,
}

/// The used prefix of `struct JNINativeInterface_`: every slot is one
/// pointer wide, so the unused runs between the named slots (with
/// their JNI-standard indices in the comments) are pointer arrays and
/// the layout stays exact. The fields are public so the fake-JNIEnv
/// harness in `tests/ffi_jni.rs` can build whole tables.
#[repr(C)]
pub struct JnInterface {
    /// Slots 0-3 are reserved and always null; plain raw pointers — an
    /// `Option<*mut c_void>` here would be 16 bytes (raw pointers have
    /// no null niche) and would shift every later slot by four.
    pub reserved: [*mut c_void; 4],
    /// Slots 4-5: GetVersion, DefineClass.
    pub gap_a: [Option<unsafe extern "system" fn()>; 2],
    /// Slot 6.
    pub find_class: Option<unsafe extern "system" fn(*mut JNIEnv, *const c_char) -> JClass>,
    /// Slots 7-12: FromReflectedMethod .. ToReflectedField.
    pub gap_b: [Option<unsafe extern "system" fn()>; 6],
    /// Slot 13.
    pub throw_fn: Option<unsafe extern "system" fn(*mut JNIEnv, Jobject) -> Jint>,
    /// Slot 14.
    pub throw_new: Option<unsafe extern "system" fn(*mut JNIEnv, JClass, *const c_char) -> Jint>,
    /// Slots 15-29: ExceptionOccurred .. EnsureLocalCapacity, AllocObject.
    pub gap_c: [Option<unsafe extern "system" fn()>; 15],
    /// Slot 30.
    pub new_object_a:
        Option<unsafe extern "system" fn(*mut JNIEnv, JClass, JmethodID, *const JValue) -> Jobject>,
    /// Slots 31-32: GetObjectClass, IsInstanceOf.
    pub gap_d: [Option<unsafe extern "system" fn()>; 2],
    /// Slot 33.
    pub get_method_id: Option<
        unsafe extern "system" fn(*mut JNIEnv, JClass, *const c_char, *const c_char) -> JmethodID,
    >,
    /// Slots 34-166: reflected/field/string/ops up to GetStringUTFLength.
    pub gap_e: [Option<unsafe extern "system" fn()>; 133],
    /// Slot 167.
    pub new_string_utf: Option<unsafe extern "system" fn(*mut JNIEnv, *const c_char) -> Jstring>,
    /// Slots 168-170: GetStringLength, GetStringChars, ReleaseStringChars.
    pub gap_f: [Option<unsafe extern "system" fn()>; 3],
    /// Slot 171.
    pub get_array_length: Option<unsafe extern "system" fn(*mut JNIEnv, Jarray) -> Jint>,
    /// Slots 172-175: NewObjectArray .. NewBooleanArray.
    pub gap_g: [Option<unsafe extern "system" fn()>; 4],
    /// Slot 176.
    pub new_byte_array: Option<unsafe extern "system" fn(*mut JNIEnv, Jint) -> JbyteArray>,
    /// Slots 177-178: NewCharArray, NewShortArray.
    pub gap_h: [Option<unsafe extern "system" fn()>; 2],
    /// Slot 179.
    pub new_int_array: Option<unsafe extern "system" fn(*mut JNIEnv, Jint) -> JintArray>,
    /// Slot 180.
    pub new_long_array: Option<unsafe extern "system" fn(*mut JNIEnv, Jint) -> JlongArray>,
    /// Slots 181-199: Get/Set regions for boolean..double.
    pub gap_i: [Option<unsafe extern "system" fn()>; 19],
    /// Slot 200.
    pub get_byte_array_region:
        Option<unsafe extern "system" fn(*mut JNIEnv, JbyteArray, Jint, Jint, *mut Jbyte)>,
    /// Slots 201-207: Get/Set regions for char..double.
    pub gap_j: [Option<unsafe extern "system" fn()>; 7],
    /// Slot 208.
    pub set_byte_array_region:
        Option<unsafe extern "system" fn(*mut JNIEnv, JbyteArray, Jint, Jint, *const Jbyte)>,
    /// Slots 209-210: SetCharArrayRegion, SetShortArrayRegion.
    pub gap_k: [Option<unsafe extern "system" fn()>; 2],
    /// Slot 211.
    pub set_int_array_region:
        Option<unsafe extern "system" fn(*mut JNIEnv, JintArray, Jint, Jint, *const Jint)>,
    /// Slot 212.
    pub set_long_array_region:
        Option<unsafe extern "system" fn(*mut JNIEnv, JlongArray, Jint, Jint, *const Jlong)>,
}

/// `JNIEnv` is itself a pointer to the function table (`typedef const
/// struct JNINativeInterface *JNIEnv;`).
pub type JNIEnv = *const JnInterface;

/// JNI binding of [`crate::detect`] for `PithHash.detect(byte[])`:
/// sniffs the input and hands back the wire triple
/// `[format, modality, pending]` as an `int[]`. A null input array or
/// a null `env` is a thrown `-1`; detection itself is infallible.
///
/// # Safety
///
/// `env` must be the `JNIEnv*` the JVM passed in (or null, which is
/// reported as `-1`); `input` must be a `jbyteArray` handle (or null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_hash_pith_PithHash_detect(
    env: *mut JNIEnv,
    _class: JClass,
    input: JbyteArray,
) -> JintArray {
    match unsafe { read_byte_array(env, input) } {
        Some(bytes) => {
            let det = crate::detect(&bytes);
            let wire = [
                i32::from(crate::reference::format_code(det.format)),
                i32::from(crate::reference::modality_code(det.modality)),
                i32::from(det.pending),
            ];
            unsafe { int_array(env, &wire) }
        }
        None => {
            unsafe { throw_status(env, "pith_hash_detect", PITH_E_INVALID) };
            core::ptr::null_mut()
        }
    }
}

/// JNI binding of [`pith_hash_signature`](crate::ffi) for
/// `PithHash.signature(byte[])`: the canonical signature stream
/// (`byte[]`) the `reference.json` vectors are defined over. A null
/// input array or a null `env` is a thrown `-1`; every refusal is a
/// thrown `-2`.
///
/// # Safety
///
/// `env` must be the `JNIEnv*` the JVM passed in (or null, which is
/// reported as `-1`); `input` must be a `jbyteArray` handle (or null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_hash_pith_PithHash_signature(
    env: *mut JNIEnv,
    _class: JClass,
    input: JbyteArray,
) -> JbyteArray {
    match unsafe { read_byte_array(env, input) } {
        Some(bytes) => unsafe { byte_array(env, "pith_hash_signature", signature_bytes(&bytes)) },
        None => {
            unsafe { throw_status(env, "pith_hash_signature", PITH_E_INVALID) };
            core::ptr::null_mut()
        }
    }
}

/// JNI binding of [`pith_hash_describe`](crate::ffi) for
/// `PithHash.describe(byte[])`: the canonical description stream
/// (`byte[]`). Same argument/refusal convention as
/// [`Java_hash_pith_PithHash_signature`].
///
/// # Safety
///
/// `env` must be the `JNIEnv*` the JVM passed in (or null, which is
/// reported as `-1`); `input` must be a `jbyteArray` handle (or null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_hash_pith_PithHash_describe(
    env: *mut JNIEnv,
    _class: JClass,
    input: JbyteArray,
) -> JbyteArray {
    match unsafe { read_byte_array(env, input) } {
        Some(bytes) => unsafe { byte_array(env, "pith_hash_describe", describe_bytes(&bytes)) },
        None => {
            unsafe { throw_status(env, "pith_hash_describe", PITH_E_INVALID) };
            core::ptr::null_mut()
        }
    }
}

/// JNI binding of [`pith_hash_match`](crate::ffi) for
/// `PithHash.match(byte[], byte[])`: the flattened outcome as a
/// `long[]` of six slots `[tag, s0, s1, s2, s3, matched]` — the
/// `u64` slot bits ride through as two's-complement `long`s. A null
/// input array or a null `env` is a thrown `-1`; every refusal
/// (including a cross-modality pair) is a thrown `-2`.
///
/// # Safety
///
/// `env` must be the `JNIEnv*` the JVM passed in (or null, which is
/// reported as `-1`); `a`/`b` must be `jbyteArray` handles (or null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_hash_pith_PithHash_match(
    env: *mut JNIEnv,
    _class: JClass,
    a: JbyteArray,
    b: JbyteArray,
) -> JlongArray {
    let (Some(a_bytes), Some(b_bytes)) = (unsafe { read_byte_array(env, a) }, unsafe {
        read_byte_array(env, b)
    }) else {
        unsafe { throw_status(env, "pith_hash_match", PITH_E_INVALID) };
        return core::ptr::null_mut();
    };
    let Ok((tag, slots, matched)) = match_slots(&a_bytes, &b_bytes) else {
        unsafe { throw_status(env, "pith_hash_match", PITH_E_REJECTED) };
        return core::ptr::null_mut();
    };
    let mut wire = [0i64; 6];
    wire[0] = i64::from(tag);
    for (slot, out) in slots.iter().zip(wire[1..5].iter_mut()) {
        *out = *slot as i64;
    }
    wire[5] = i64::from(matched);
    unsafe { long_array(env, &wire) }
}

/// JNI binding of [`pith_hash_content_hash`](crate::ffi) for
/// `PithHash.contentHash(byte[])`: the 32-byte content digest
/// (`byte[]`). A null input array or a null `env` is a thrown `-1`;
/// every refusal is a thrown `-2`.
///
/// # Safety
///
/// `env` must be the `JNIEnv*` the JVM passed in (or null, which is
/// reported as `-1`); `input` must be a `jbyteArray` handle (or null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_hash_pith_PithHash_contentHash(
    env: *mut JNIEnv,
    _class: JClass,
    input: JbyteArray,
) -> JbyteArray {
    let result = match unsafe { read_byte_array(env, input) } {
        Some(bytes) => crate::content_hash(&bytes)
            .map(|digest| Vec::from(digest.as_bytes()))
            .map_err(|_| PITH_E_REJECTED),
        None => Err(PITH_E_INVALID),
    };
    match result {
        Ok(bytes) => unsafe { byte_array(env, "pith_hash_content_hash", Ok(bytes)) },
        Err(status) => {
            unsafe { throw_status(env, "pith_hash_content_hash", status) };
            core::ptr::null_mut()
        }
    }
}

/// Reads a Java `byte[]` through `env` into a native buffer. `None`
/// for a null `env` or a null array — the caller maps that to `-1`.
///
/// # Safety
///
/// `env` must be a valid JVM environment or null; `array` must be a
/// `jbyteArray` handle owned by the caller or null.
unsafe fn read_byte_array(env: *mut JNIEnv, array: JbyteArray) -> Option<Vec<u8>> {
    if env.is_null() || array.is_null() {
        return None;
    }
    let table = unsafe { &*(*env) };
    let len = unsafe { (table.get_array_length.expect("GetArrayLength slot"))(env, array) };
    let mut bytes = alloc::vec![0u8; len as usize];
    unsafe {
        (table
            .get_byte_array_region
            .expect("GetByteArrayRegion slot"))(
            env, array, 0, len, bytes.as_mut_ptr().cast()
        )
    };
    Some(bytes)
}

/// Copies a safe-core result into a fresh Java `byte[]`; a refusal
/// throws and returns null. A failed `NewByteArray` (the JVM has a
/// pending `OutOfMemoryError`) returns null without throwing.
///
/// # Safety
///
/// `env` must be a valid JVM environment or null.
unsafe fn byte_array(env: *mut JNIEnv, op: &str, result: Result<Vec<u8>, i32>) -> JbyteArray {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(status) => {
            unsafe { throw_status(env, op, status) };
            return core::ptr::null_mut();
        }
    };
    let table = unsafe { &*(*env) };
    let array =
        unsafe { (table.new_byte_array.expect("NewByteArray slot"))(env, bytes.len() as Jint) };
    if array.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        (table
            .set_byte_array_region
            .expect("SetByteArrayRegion slot"))(
            env,
            array,
            0,
            bytes.len() as Jint,
            bytes.as_ptr().cast(),
        )
    };
    array
}

/// Copies `values` into a fresh Java `int[]`; a failed `NewIntArray`
/// (the JVM has a pending `OutOfMemoryError`) returns null without
/// throwing. A null `env` returns null quietly.
///
/// # Safety
///
/// `env` must be a valid JVM environment or null.
unsafe fn int_array(env: *mut JNIEnv, values: &[Jint]) -> JintArray {
    if env.is_null() {
        return core::ptr::null_mut();
    }
    let table = unsafe { &*(*env) };
    let array =
        unsafe { (table.new_int_array.expect("NewIntArray slot"))(env, values.len() as Jint) };
    if array.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        (table.set_int_array_region.expect("SetIntArrayRegion slot"))(
            env,
            array,
            0,
            values.len() as Jint,
            values.as_ptr(),
        )
    };
    array
}

/// Copies `values` into a fresh Java `long[]`; a failed `NewLongArray`
/// returns null without throwing. A null `env` returns null quietly.
///
/// # Safety
///
/// `env` must be a valid JVM environment or null.
unsafe fn long_array(env: *mut JNIEnv, values: &[Jlong]) -> JlongArray {
    if env.is_null() {
        return core::ptr::null_mut();
    }
    let table = unsafe { &*(*env) };
    let array =
        unsafe { (table.new_long_array.expect("NewLongArray slot"))(env, values.len() as Jint) };
    if array.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        (table
            .set_long_array_region
            .expect("SetLongArrayRegion slot"))(
            env,
            array,
            0,
            values.len() as Jint,
            values.as_ptr(),
        )
    };
    array
}

/// Throws `hash.pith.PithFfiException(status, "<op> failed with
/// status <status>")`; every resolution failure on the way falls back
/// to `ThrowNew(java.lang.RuntimeException)`. A null `env` has no JVM
/// to throw into and returns quietly (the Java caller sees `null`).
///
/// # Safety
///
/// `env` must be a valid JVM environment or null.
unsafe fn throw_status(env: *mut JNIEnv, op: &str, status: i32) {
    if env.is_null() {
        return;
    }
    let table = unsafe { &*(*env) };
    let Ok(text) = CString::new(alloc::format!("{op} failed with status {status}")) else {
        return;
    };
    let class = unsafe {
        (table.find_class.expect("FindClass slot"))(env, c"hash/pith/PithFfiException".as_ptr())
    };
    if class.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    let ctor = unsafe {
        (table.get_method_id.expect("GetMethodID slot"))(
            env,
            class,
            c"<init>".as_ptr(),
            c"(Ljava/lang/String;I)V".as_ptr(),
        )
    };
    if ctor.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    let message = unsafe { (table.new_string_utf.expect("NewStringUTF slot"))(env, text.as_ptr()) };
    if message.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    let args = [
        JValue {
            object_value: message,
        },
        JValue { int_value: status },
    ];
    let thrown =
        unsafe { (table.new_object_a.expect("NewObjectA slot"))(env, class, ctor, args.as_ptr()) };
    if thrown.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    unsafe { (table.throw_fn.expect("Throw slot"))(env, thrown) };
}

/// The `ThrowNew(java.lang.RuntimeException, msg)` fallback for when
/// the typed exception cannot be constructed.
///
/// # Safety
///
/// `env` must be a valid JVM environment; `table` must be the table
/// `env` points at; `text` must be a valid C string.
unsafe fn throw_runtime(env: *mut JNIEnv, table: &JnInterface, text: &CString) {
    let class = unsafe {
        (table.find_class.expect("FindClass slot"))(env, c"java/lang/RuntimeException".as_ptr())
    };
    if !class.is_null() {
        unsafe { (table.throw_new.expect("ThrowNew slot"))(env, class, text.as_ptr()) };
    }
}
