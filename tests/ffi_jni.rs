//! The fake-JNIEnv scenarios for [`pith_hash::ffi_jni`]. The JNI
//! surface compiles only into the normal flavor (the same reason `ffi`
//! does — see `src/lib.rs`), so these run as an integration test that
//! links the normal flavor instead of as in-module unit tests: the
//! exports the harness exercises are the same copies the cdylib ships.

use std::cell::{Cell, RefCell};
use std::path::Path;

use pith_hash::ffi_jni::{
    JNIEnv, JValue, Java_hash_pith_PithHash_contentHash, Java_hash_pith_PithHash_describe,
    Java_hash_pith_PithHash_detect, Java_hash_pith_PithHash_match,
    Java_hash_pith_PithHash_signature, JbyteArray, JnInterface,
};
use pith_hash::{describe, reference, signature};

thread_local! {
    static JVM: Jvm = Jvm::default();
}

/// One array handle's storage: the fake slots keep every array kind in
/// one index space (`handle == index + 1`).
enum Slot {
    Bytes(Vec<u8>),
    Ints(Vec<i32>),
    Longs(Vec<i64>),
}

/// The fake JVM state the fake slots operate on: canned array storage
/// plus failure masks that drive every defensive arm.
#[derive(Default)]
struct Jvm {
    /// Fails only the FIRST FindClass (the typed exception), so
    /// the RuntimeException fallback lookup still succeeds.
    fail_first_find_class: Cell<bool>,
    find_class_calls: Cell<u32>,
    fail_method_id: Cell<bool>,
    fail_string: Cell<bool>,
    fail_new_object: Cell<bool>,
    fail_new_byte_array: Cell<bool>,
    fail_new_int_array: Cell<bool>,
    /// The status argument the last `NewObjectA` saw (0 = none).
    pending_status: Cell<i32>,
    /// Whether the fake `Throw` ran.
    threw: Cell<bool>,
    /// How many times the `ThrowNew` fallback ran.
    throw_new_calls: Cell<u32>,
    /// Array handles are `(index + 1)` cast to a pointer.
    arrays: RefCell<Vec<Slot>>,
}

fn reset() {
    JVM.with(|j| {
        j.fail_first_find_class.set(false);
        j.find_class_calls.set(0);
        j.fail_method_id.set(false);
        j.fail_string.set(false);
        j.fail_new_object.set(false);
        j.fail_new_byte_array.set(false);
        j.fail_new_int_array.set(false);
        j.pending_status.set(0);
        j.threw.set(false);
        j.throw_new_calls.set(0);
        j.arrays.borrow_mut().clear();
    });
}

fn push_array(bytes: &[u8]) -> JbyteArray {
    JVM.with(|j| {
        j.arrays.borrow_mut().push(Slot::Bytes(bytes.to_vec()));
        j.arrays.borrow().len() as JbyteArray
    })
}

fn array_bytes(handle: JbyteArray) -> Vec<u8> {
    JVM.with(|j| match &j.arrays.borrow()[(handle as usize) - 1] {
        Slot::Bytes(bytes) => bytes.clone(),
        _ => panic!("not a byte array"),
    })
}

fn int_array_values(handle: pith_hash::ffi_jni::JintArray) -> Vec<i32> {
    JVM.with(|j| match &j.arrays.borrow()[(handle as usize) - 1] {
        Slot::Ints(values) => values.clone(),
        _ => panic!("not an int array"),
    })
}

fn long_array_values(handle: pith_hash::ffi_jni::JlongArray) -> Vec<i64> {
    JVM.with(|j| match &j.arrays.borrow()[(handle as usize) - 1] {
        Slot::Longs(values) => values.clone(),
        _ => panic!("not a long array"),
    })
}

use core::ffi::{c_char, c_void};

unsafe extern "system" fn fake_find_class(
    _env: *mut JNIEnv,
    _name: *const c_char,
) -> pith_hash::ffi_jni::JClass {
    JVM.with(|j| {
        let call = j.find_class_calls.get();
        j.find_class_calls.set(call + 1);
        if call == 0 && j.fail_first_find_class.get() {
            core::ptr::null_mut()
        } else {
            0x10usize as pith_hash::ffi_jni::JClass
        }
    })
}

unsafe extern "system" fn fake_throw_fn(
    _env: *mut JNIEnv,
    _obj: pith_hash::ffi_jni::Jobject,
) -> i32 {
    JVM.with(|j| j.threw.set(true));
    0
}

unsafe extern "system" fn fake_throw_new(
    _env: *mut JNIEnv,
    _class: pith_hash::ffi_jni::JClass,
    _msg: *const c_char,
) -> i32 {
    JVM.with(|j| j.throw_new_calls.set(j.throw_new_calls.get() + 1));
    0
}

unsafe extern "system" fn fake_new_object_a(
    _env: *mut JNIEnv,
    _class: pith_hash::ffi_jni::JClass,
    _method: pith_hash::ffi_jni::JmethodID,
    args: *const JValue,
) -> pith_hash::ffi_jni::Jobject {
    JVM.with(|j| {
        if j.fail_new_object.get() {
            core::ptr::null_mut()
        } else {
            j.pending_status.set(unsafe { (*args.add(1)).int_value });
            0x40usize as pith_hash::ffi_jni::Jobject
        }
    })
}

unsafe extern "system" fn fake_get_method_id(
    _env: *mut JNIEnv,
    _class: pith_hash::ffi_jni::JClass,
    _name: *const c_char,
    _sig: *const c_char,
) -> pith_hash::ffi_jni::JmethodID {
    JVM.with(|j| {
        if j.fail_method_id.get() {
            core::ptr::null_mut()
        } else {
            0x20usize as pith_hash::ffi_jni::JmethodID
        }
    })
}

unsafe extern "system" fn fake_new_string_utf(
    _env: *mut JNIEnv,
    _text: *const c_char,
) -> pith_hash::ffi_jni::Jstring {
    JVM.with(|j| {
        if j.fail_string.get() {
            core::ptr::null_mut()
        } else {
            0x30usize as pith_hash::ffi_jni::Jstring
        }
    })
}

unsafe extern "system" fn fake_get_array_length(
    _env: *mut JNIEnv,
    array: pith_hash::ffi_jni::Jarray,
) -> i32 {
    JVM.with(|j| {
        let arrays = j.arrays.borrow();
        match &arrays[(array as usize) - 1] {
            Slot::Bytes(bytes) => bytes.len() as i32,
            Slot::Ints(values) => values.len() as i32,
            Slot::Longs(values) => values.len() as i32,
        }
    })
}

unsafe extern "system" fn fake_new_byte_array(_env: *mut JNIEnv, len: i32) -> JbyteArray {
    JVM.with(|j| {
        if j.fail_new_byte_array.get() {
            core::ptr::null_mut()
        } else {
            j.arrays
                .borrow_mut()
                .push(Slot::Bytes(vec![0u8; len as usize]));
            j.arrays.borrow().len() as JbyteArray
        }
    })
}

unsafe extern "system" fn fake_new_int_array(
    _env: *mut JNIEnv,
    len: i32,
) -> pith_hash::ffi_jni::JintArray {
    JVM.with(|j| {
        if j.fail_new_int_array.get() {
            core::ptr::null_mut()
        } else {
            j.arrays
                .borrow_mut()
                .push(Slot::Ints(vec![0i32; len as usize]));
            j.arrays.borrow().len() as pith_hash::ffi_jni::JintArray
        }
    })
}

unsafe extern "system" fn fake_new_long_array(
    _env: *mut JNIEnv,
    len: i32,
) -> pith_hash::ffi_jni::JlongArray {
    JVM.with(|j| {
        j.arrays
            .borrow_mut()
            .push(Slot::Longs(vec![0i64; len as usize]));
        j.arrays.borrow().len() as pith_hash::ffi_jni::JlongArray
    })
}

unsafe extern "system" fn fake_get_byte_array_region(
    _env: *mut JNIEnv,
    array: JbyteArray,
    start: i32,
    len: i32,
    out: *mut i8,
) {
    let src = JVM.with(|j| match &j.arrays.borrow()[(array as usize) - 1] {
        Slot::Bytes(bytes) => bytes[start as usize..(start + len) as usize].to_vec(),
        _ => panic!("not a byte array"),
    });
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().cast(), out, src.len()) };
}

unsafe extern "system" fn fake_set_byte_array_region(
    _env: *mut JNIEnv,
    array: JbyteArray,
    start: i32,
    len: i32,
    data: *const i8,
) {
    JVM.with(|j| match &mut j.arrays.borrow_mut()[(array as usize) - 1] {
        Slot::Bytes(bytes) => unsafe {
            core::ptr::copy_nonoverlapping(
                data.cast(),
                bytes[start as usize..].as_mut_ptr(),
                len as usize,
            );
        },
        _ => panic!("not a byte array"),
    });
}

unsafe extern "system" fn fake_set_int_array_region(
    _env: *mut JNIEnv,
    array: pith_hash::ffi_jni::JintArray,
    start: i32,
    len: i32,
    data: *const i32,
) {
    JVM.with(|j| match &mut j.arrays.borrow_mut()[(array as usize) - 1] {
        Slot::Ints(values) => unsafe {
            core::ptr::copy_nonoverlapping(
                data,
                values[start as usize..].as_mut_ptr(),
                len as usize,
            );
        },
        _ => panic!("not an int array"),
    });
}

unsafe extern "system" fn fake_set_long_array_region(
    _env: *mut JNIEnv,
    array: pith_hash::ffi_jni::JlongArray,
    start: i32,
    len: i32,
    data: *const i64,
) {
    JVM.with(|j| match &mut j.arrays.borrow_mut()[(array as usize) - 1] {
        Slot::Longs(values) => unsafe {
            core::ptr::copy_nonoverlapping(
                data,
                values[start as usize..].as_mut_ptr(),
                len as usize,
            );
        },
        _ => panic!("not a long array"),
    });
}

fn fake_table() -> JnInterface {
    JnInterface {
        reserved: [core::ptr::null_mut::<c_void>(); 4],
        gap_a: [None; 2],
        find_class: Some(fake_find_class),
        gap_b: [None; 6],
        throw_fn: Some(fake_throw_fn),
        throw_new: Some(fake_throw_new),
        gap_c: [None; 15],
        new_object_a: Some(fake_new_object_a),
        gap_d: [None; 2],
        get_method_id: Some(fake_get_method_id),
        gap_e: [None; 133],
        new_string_utf: Some(fake_new_string_utf),
        gap_f: [None; 3],
        get_array_length: Some(fake_get_array_length),
        gap_g: [None; 4],
        new_byte_array: Some(fake_new_byte_array),
        gap_h: [None; 2],
        new_int_array: Some(fake_new_int_array),
        new_long_array: Some(fake_new_long_array),
        gap_i: [None; 19],
        get_byte_array_region: Some(fake_get_byte_array_region),
        gap_j: [None; 7],
        set_byte_array_region: Some(fake_set_byte_array_region),
        gap_k: [None; 2],
        set_int_array_region: Some(fake_set_int_array_region),
        set_long_array_region: Some(fake_set_long_array_region),
    }
}

/// A `*mut JNIEnv` pointing at a leaked-then-dropped fake table.
struct EnvGuard(*mut JNIEnv);

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(*self.0 as *mut JnInterface));
            drop(Box::from_raw(self.0));
        }
    }
}

fn fake_env() -> EnvGuard {
    let table: JNIEnv = Box::into_raw(Box::new(fake_table()));
    EnvGuard(Box::into_raw(Box::new(table)))
}

fn fixture(name: &str) -> Vec<u8> {
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    std::fs::read(Path::new(&root).join("tests").join("fixtures").join(name)).expect("fixture")
}

const NULL_CLASS: pith_hash::ffi_jni::JClass = core::ptr::null_mut();

#[test]
fn struct_layout_matches_the_jni_slot_order() {
    assert_eq!(std::mem::size_of::<JnInterface>(), 213 * 8);
    let slot = |i: usize| i * 8;
    assert_eq!(std::mem::offset_of!(JnInterface, find_class), slot(6));
    assert_eq!(std::mem::offset_of!(JnInterface, throw_fn), slot(13));
    assert_eq!(std::mem::offset_of!(JnInterface, throw_new), slot(14));
    assert_eq!(std::mem::offset_of!(JnInterface, new_object_a), slot(30));
    assert_eq!(std::mem::offset_of!(JnInterface, get_method_id), slot(33));
    assert_eq!(std::mem::offset_of!(JnInterface, new_string_utf), slot(167));
    assert_eq!(
        std::mem::offset_of!(JnInterface, get_array_length),
        slot(171)
    );
    assert_eq!(std::mem::offset_of!(JnInterface, new_byte_array), slot(176));
    assert_eq!(std::mem::offset_of!(JnInterface, new_int_array), slot(179));
    assert_eq!(std::mem::offset_of!(JnInterface, new_long_array), slot(180));
    assert_eq!(
        std::mem::offset_of!(JnInterface, get_byte_array_region),
        slot(200)
    );
    assert_eq!(
        std::mem::offset_of!(JnInterface, set_byte_array_region),
        slot(208)
    );
    assert_eq!(
        std::mem::offset_of!(JnInterface, set_int_array_region),
        slot(211)
    );
    assert_eq!(
        std::mem::offset_of!(JnInterface, set_long_array_region),
        slot(212)
    );
}

#[test]
fn detect_happy_png_returns_the_wire_triple() {
    reset();
    let env = fake_env();
    let input = fixture("phash_rgb8_48x40.png");
    let out = unsafe { Java_hash_pith_PithHash_detect(env.0, NULL_CLASS, push_array(&input)) };
    assert!(!out.is_null());
    assert_eq!(int_array_values(out), vec![0, 0, 0]);
    let jvm = JVM.with(|j| {
        (
            j.pending_status.get(),
            j.threw.get(),
            j.throw_new_calls.get(),
        )
    });
    assert_eq!(jvm, (0, false, 0));
}

#[test]
fn detect_gif_is_binary_modality() {
    reset();
    let env = fake_env();
    let out =
        unsafe { Java_hash_pith_PithHash_detect(env.0, NULL_CLASS, push_array(b"GIF89a payload")) };
    assert_eq!(int_array_values(out), vec![9, 3, 0]);
}

#[test]
fn detect_zip_magic_is_binary_modality() {
    reset();
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_detect(env.0, NULL_CLASS, push_array(b"PK\x03\x04 archive"))
    };
    assert_eq!(int_array_values(out), vec![3, 3, 0]);
}

#[test]
fn detect_null_input_array_throws_invalid() {
    reset();
    let env = fake_env();
    let out = unsafe { Java_hash_pith_PithHash_detect(env.0, NULL_CLASS, core::ptr::null_mut()) };
    assert!(out.is_null());
    assert_eq!(JVM.with(|j| j.pending_status.get()), -1);
    assert!(JVM.with(|j| j.threw.get()));
}

#[test]
fn detect_null_env_is_null_without_panicking() {
    reset();
    let out = unsafe {
        Java_hash_pith_PithHash_detect(core::ptr::null_mut(), NULL_CLASS, core::ptr::null_mut())
    };
    assert!(out.is_null());
    assert!(!JVM.with(|j| j.threw.get()));
}

#[test]
fn signature_happy_matches_the_safe_core() {
    reset();
    let env = fake_env();
    let input = fixture("phash_rgb8_48x40.png");
    let expected = reference::signature_stream(&signature(&input).unwrap());
    let out = unsafe { Java_hash_pith_PithHash_signature(env.0, NULL_CLASS, push_array(&input)) };
    assert!(!out.is_null());
    assert_eq!(array_bytes(out), expected);
    let jvm = JVM.with(|j| {
        (
            j.pending_status.get(),
            j.threw.get(),
            j.throw_new_calls.get(),
        )
    });
    assert_eq!(jvm, (0, false, 0));
}

#[test]
fn describe_happy_matches_the_safe_core() {
    reset();
    let env = fake_env();
    let input = fixture("phash_rgb8_48x40.png");
    let expected = reference::describe_stream(&describe(&input).unwrap());
    let out = unsafe { Java_hash_pith_PithHash_describe(env.0, NULL_CLASS, push_array(&input)) };
    assert!(!out.is_null());
    assert_eq!(array_bytes(out), expected);
}

#[test]
fn match_happy_identical_blobs_is_matched_image() {
    reset();
    let env = fake_env();
    let input = fixture("phash_rgb8_48x40.png");
    let handle = push_array(&input);
    let out = unsafe { Java_hash_pith_PithHash_match(env.0, NULL_CLASS, handle, handle) };
    assert!(!out.is_null());
    // tag 0 (image), slots[0] = hamming 0, matched 1.
    assert_eq!(long_array_values(out), vec![0, 0, 0, 0, 0, 1]);
    let jvm = JVM.with(|j| (j.pending_status.get(), j.threw.get()));
    assert_eq!(jvm, (0, false));
}

#[test]
fn match_cross_modality_throws_rejected() {
    reset();
    let env = fake_env();
    let a = push_array(&fixture("phash_rgb8_48x40.png"));
    let b = push_array(&b"just some words".repeat(64));
    let out = unsafe { Java_hash_pith_PithHash_match(env.0, NULL_CLASS, a, b) };
    assert!(out.is_null());
    assert_eq!(
        JVM.with(|j| (j.pending_status.get(), j.threw.get())),
        (-2, true)
    );
}

#[test]
fn match_null_input_array_throws_invalid() {
    reset();
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_match(
            env.0,
            NULL_CLASS,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert!(out.is_null());
    assert_eq!(JVM.with(|j| j.pending_status.get()), -1);
}

#[test]
fn content_hash_happy_is_32_digest_bytes() {
    reset();
    let env = fake_env();
    let input = fixture("phash_rgb8_48x40.png");
    let expected = pith_hash::content_hash(&input).unwrap();
    let out = unsafe { Java_hash_pith_PithHash_contentHash(env.0, NULL_CLASS, push_array(&input)) };
    assert!(!out.is_null());
    assert_eq!(array_bytes(out), expected.as_bytes().to_vec());
    assert_eq!(array_bytes(out).len(), 32);
}

#[test]
fn content_hash_garbage_throws_rejected() {
    reset();
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_contentHash(
            env.0,
            NULL_CLASS,
            push_array(b"\x89PNG\r\n\x1a\ngarbage"),
        )
    };
    assert!(out.is_null());
    assert_eq!(
        JVM.with(|j| (j.pending_status.get(), j.threw.get())),
        (-2, true)
    );
}

#[test]
fn garbage_signature_throws_rejected() {
    reset();
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(
            env.0,
            NULL_CLASS,
            push_array(b"\x89PNG\r\n\x1a\ngarbage"),
        )
    };
    assert!(out.is_null());
    assert_eq!(
        JVM.with(|j| (j.pending_status.get(), j.threw.get())),
        (-2, true)
    );
}

#[test]
fn corrupt_png_refuses_everywhere() {
    let corrupt = b"\x89PNG\r\n\x1a\ngarbage";
    for run in [
        |env: *mut JNIEnv, input: JbyteArray| unsafe {
            Java_hash_pith_PithHash_signature(env, NULL_CLASS, input)
        },
        |env: *mut JNIEnv, input: JbyteArray| unsafe {
            Java_hash_pith_PithHash_describe(env, NULL_CLASS, input)
        },
        |env: *mut JNIEnv, input: JbyteArray| unsafe {
            Java_hash_pith_PithHash_contentHash(env, NULL_CLASS, input)
        },
    ] {
        reset();
        let env = fake_env();
        let out = run(env.0, push_array(corrupt));
        assert!(out.is_null());
        assert_eq!(
            JVM.with(|j| (j.pending_status.get(), j.threw.get())),
            (-2, true)
        );
    }
}

#[test]
fn null_input_array_throws_invalid() {
    reset();
    let env = fake_env();
    let out =
        unsafe { Java_hash_pith_PithHash_signature(env.0, NULL_CLASS, core::ptr::null_mut()) };
    assert!(out.is_null());
    assert_eq!(JVM.with(|j| j.pending_status.get()), -1);
    assert!(JVM.with(|j| j.threw.get()));
}

#[test]
fn null_env_is_null_without_panicking() {
    reset();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(core::ptr::null_mut(), NULL_CLASS, core::ptr::null_mut())
    };
    assert!(out.is_null());
    assert!(!JVM.with(|j| j.threw.get()));
    let out = unsafe {
        Java_hash_pith_PithHash_match(
            core::ptr::null_mut(),
            NULL_CLASS,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert!(out.is_null());
}

#[test]
fn failed_new_byte_array_returns_null_without_throwing() {
    reset();
    JVM.with(|j| j.fail_new_byte_array.set(true));
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(
            env.0,
            NULL_CLASS,
            push_array(&fixture("phash_rgb8_48x40.png")),
        )
    };
    assert!(out.is_null());
    let jvm = JVM.with(|j| {
        (
            j.pending_status.get(),
            j.threw.get(),
            j.throw_new_calls.get(),
        )
    });
    assert_eq!(jvm, (0, false, 0));
}

#[test]
fn failed_new_int_array_returns_null_without_throwing() {
    reset();
    JVM.with(|j| j.fail_new_int_array.set(true));
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_detect(
            env.0,
            NULL_CLASS,
            push_array(&fixture("phash_rgb8_48x40.png")),
        )
    };
    assert!(out.is_null());
    let jvm = JVM.with(|j| {
        (
            j.pending_status.get(),
            j.threw.get(),
            j.throw_new_calls.get(),
        )
    });
    assert_eq!(jvm, (0, false, 0));
}

#[test]
fn unresolvable_exception_class_falls_back_to_throw_new() {
    reset();
    JVM.with(|j| j.fail_first_find_class.set(true));
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(
            env.0,
            NULL_CLASS,
            push_array(b"\x89PNG\r\n\x1a\ngarbage"),
        )
    };
    assert!(out.is_null());
    let jvm = JVM.with(|j| {
        (
            j.pending_status.get(),
            j.threw.get(),
            j.throw_new_calls.get(),
        )
    });
    assert_eq!(jvm, (0, false, 1));
}

#[test]
fn unresolvable_ctor_falls_back_to_throw_new() {
    reset();
    JVM.with(|j| j.fail_method_id.set(true));
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(
            env.0,
            NULL_CLASS,
            push_array(b"\x89PNG\r\n\x1a\ngarbage"),
        )
    };
    assert!(out.is_null());
    assert_eq!(JVM.with(|j| j.throw_new_calls.get()), 1);
}

#[test]
fn failed_message_string_falls_back_to_throw_new() {
    reset();
    JVM.with(|j| j.fail_string.set(true));
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(
            env.0,
            NULL_CLASS,
            push_array(b"\x89PNG\r\n\x1a\ngarbage"),
        )
    };
    assert!(out.is_null());
    assert_eq!(JVM.with(|j| j.throw_new_calls.get()), 1);
}

#[test]
fn failed_exception_object_falls_back_to_throw_new() {
    reset();
    JVM.with(|j| j.fail_new_object.set(true));
    let env = fake_env();
    let out = unsafe {
        Java_hash_pith_PithHash_signature(
            env.0,
            NULL_CLASS,
            push_array(b"\x89PNG\r\n\x1a\ngarbage"),
        )
    };
    assert!(out.is_null());
    assert_eq!(JVM.with(|j| j.throw_new_calls.get()), 1);
}
