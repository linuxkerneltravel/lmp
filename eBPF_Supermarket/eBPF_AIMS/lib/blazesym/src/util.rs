use std::cmp::Ordering;
use std::ffi::CStr;
use std::ffi::CString;
use std::io;
use std::iter;
use std::mem::align_of;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::ptr::NonNull;
use std::slice;


/// Reorder elements of `array` based on index information in `indices`.
fn reorder<T, U>(array: &mut [T], indices: Vec<(U, usize)>) {
    debug_assert_eq!(array.len(), indices.len());

    let mut indices = indices;
    // Sort the entries in `array` based on the indexes in `indices`
    // (second member).
    for i in 0..array.len() {
        while indices[i].1 != i {
            let () = array.swap(i, indices[i].1);
            let idx = indices[i].1;
            let () = indices.swap(i, idx);
        }
    }
}


/// Take a slice `slice` of unordered elements, sort them into a vector, then
/// invoke a function `handle` on the vector, take the result of this function
/// and "extract" a mutable reference to a slice, reordered this slice in such a
/// way that the original order of `slice` is preserved.
pub(crate) fn with_ordered_elems<T, U, E, H, R, Err>(
    slice: &[T],
    extract: E,
    handle: H,
) -> Result<R, Err>
where
    T: Copy + Ord,
    E: FnOnce(&mut R) -> &mut [U],
    H: FnOnce(iter::Map<slice::Iter<'_, (T, usize)>, fn(&(T, usize)) -> T>) -> Result<R, Err>,
{
    let mut vec = slice
        .iter()
        .enumerate()
        .map(|(idx, t)| (*t, idx))
        .collect::<Vec<_>>();
    let () = vec.sort_unstable();

    let mut result = handle(vec.iter().map(|(t, _idx)| *t))?;
    let () = reorder(extract(&mut result), vec);
    Ok(result)
}


/// "Safely" create a slice from a user provided array.
pub(crate) unsafe fn slice_from_user_array<'t, T>(items: *const T, num_items: usize) -> &'t [T] {
    let items = if items.is_null() {
        // `slice::from_raw_parts` requires a properly aligned non-NULL pointer.
        // Craft one.
        NonNull::dangling().as_ptr()
    } else {
        items
    };
    unsafe { slice::from_raw_parts(items, num_items) }
}

pub(crate) fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut dst = MaybeUninit::uninit();
    let rc = unsafe { libc::fstat(fd, dst.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
    }

    // SAFETY: The object is initialized on success of `fstat`.
    Ok(unsafe { dst.assume_init() })
}

pub(crate) fn uname_release() -> io::Result<CString> {
    let mut dst = MaybeUninit::uninit();
    let rc = unsafe { libc::uname(dst.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error())
    }

    // SAFETY: The object is initialized on success of `uname`.
    let uname = unsafe { dst.assume_init() };
    // SAFETY: `uname` ensures a NUL terminated string in `uname.release` on
    //         success.
    let release = unsafe { CStr::from_ptr(uname.release.as_ptr()) }.to_owned();
    Ok(release)
}

pub(crate) fn find_lowest_match_by<T, F>(slice: &[T], mut f: F) -> Option<usize>
where
    F: FnMut(&T) -> Ordering,
{
    let idx = slice.partition_point(|e| f(e).is_lt());
    if let Some(e) = slice.get(idx) {
        if f(e).is_eq() {
            return Some(idx)
        }
    }
    None
}

#[allow(dead_code)]
pub(crate) fn find_lowest_match_by_key<T, B, F>(slice: &[T], b: &B, mut f: F) -> Option<usize>
where
    F: FnMut(&T) -> B,
    B: Ord,
{
    find_lowest_match_by(slice, |k| f(k).cmp(b))
}

#[cfg(test)]
pub(crate) fn find_lowest_match<T>(slice: &[T], item: &T) -> Option<usize>
where
    T: Ord,
{
    find_lowest_match_by(slice, |elem| elem.cmp(item))
}

/// See `find_match_or_lower_bound`, but allow the user to pass in a comparison
/// function for increased flexibility.
pub(crate) fn find_match_or_lower_bound_by_key<T, U, F>(
    slice: &[T],
    item: U,
    mut f: F,
) -> Option<usize>
where
    U: Ord,
    F: FnMut(&T) -> U,
{
    let idx = slice.partition_point(|e| f(e) < item);

    // At this point `idx` references the first item greater or equal to the one
    // we are looking for.

    if let Some(e) = slice.get(idx) {
        // If the item at `idx` is equal to what we were looking for, we are
        // trivially done, as it's guaranteed to be the first one to match.
        if f(e) == item {
            return Some(idx)
        }
    }

    // Otherwise `idx` points to a "greater" item. Hence, we pick the previous
    // one, but then have to scan backwards for as long as we see this one item,
    // so that we end up reporting the index of the first of all equal ones.
    let idx = idx.checked_sub(1)?;
    let cmp_e = f(slice.get(idx)?);

    for i in (0..idx).rev() {
        let e = slice.get(i)?;
        if f(e) != cmp_e {
            return Some(i + 1)
        }
    }
    Some(idx)
}

/// Perform a binary search on a slice, returning the index of the match (if
/// found) or the one of the previous item (if any), taking into account
/// duplicates.
///
/// This functionality is useful for cases where we compare elements with a
/// size, such as ranges, and an address to search for can be covered by a range
/// whose start is before the item to search for.
pub(crate) fn find_match_or_lower_bound<T>(slice: &[T], item: T) -> Option<usize>
where
    T: Copy + Ord,
{
    find_match_or_lower_bound_by_key(slice, item, |e| *e)
}


/// A marker trait for "plain old data" data types.
///
/// # Safety
/// Only safe to implement for types that are valid for any bit pattern.
pub(crate) unsafe trait Pod {}

unsafe impl Pod for i8 {}
unsafe impl Pod for u8 {}
unsafe impl Pod for i16 {}
unsafe impl Pod for u16 {}
unsafe impl Pod for i32 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for i64 {}
unsafe impl Pod for u64 {}
unsafe impl Pod for i128 {}
unsafe impl Pod for u128 {}

/// An trait providing utility functions for reading data from a byte buffer.
pub(crate) trait ReadRaw<'data> {
    /// Ensure that `len` bytes are available for consumption.
    fn ensure(&self, len: usize) -> Option<()>;

    /// Align the read pointer to the next multiple of `align_to`.
    ///
    /// # Panics
    /// This method may panic if `align_to` is not a power of two.
    fn align(&mut self, align_to: usize) -> Option<()>;

    /// Consume and return `len` bytes.
    fn read_slice(&mut self, len: usize) -> Option<&'data [u8]>;

    /// Read a NUL terminated string.
    fn read_cstr(&mut self) -> Option<&'data CStr>;

    /// Read anything implementing `Pod`.
    #[inline]
    fn read_pod<T>(&mut self) -> Option<T>
    where
        T: Pod,
    {
        let data = self.read_slice(size_of::<T>())?;
        // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
        //         is guaranteed to be valid and to point to memory of at least
        //         `sizeof(T)` bytes.
        let value = unsafe { data.as_ptr().cast::<T>().read_unaligned() };
        Some(value)
    }

    /// Read a reference to something implementing `Pod`.
    #[inline]
    fn read_pod_ref<T>(&mut self) -> Option<&'data T>
    where
        T: Pod,
    {
        let data = self.read_slice(size_of::<T>())?;
        let ptr = data.as_ptr();

        if ptr.align_offset(align_of::<T>()) == 0 {
            // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
            //         is guaranteed to be valid and to point to memory of at least
            //         `sizeof(T)` bytes. We know it is properly aligned
            //         because we checked that.
            unsafe { ptr.cast::<T>().as_ref() }
        } else {
            None
        }
    }

    /// Read a reference to something implementing `Pod`.
    #[inline]
    fn read_pod_slice_ref<T>(&mut self, count: usize) -> Option<&'data [T]>
    where
        T: Pod,
    {
        let data = self.read_slice(size_of::<T>().checked_mul(count)?)?;
        let ptr = data.as_ptr();

        if ptr.align_offset(align_of::<T>()) == 0 {
            // SAFETY: `T` is `Pod` and hence valid for any bit pattern. The pointer
            //         is guaranteed to be valid and to point to memory of at least
            //         `sizeof(T)` bytes. We know it is properly aligned
            //         because we checked that.
            Some(unsafe { slice::from_raw_parts(ptr.cast::<T>(), count) })
        } else {
            None
        }
    }

    /// Read a `u8` value.
    #[inline]
    fn read_u8(&mut self) -> Option<u8> {
        self.read_pod::<u8>()
    }

    /// Read a `i16` value.
    #[inline]
    fn read_i16(&mut self) -> Option<i16> {
        self.read_pod::<i16>()
    }

    /// Read a `u16` value.
    #[inline]
    fn read_u16(&mut self) -> Option<u16> {
        self.read_pod::<u16>()
    }

    /// Read a `i32` value.
    #[inline]
    fn read_i32(&mut self) -> Option<i32> {
        self.read_pod::<i32>()
    }

    /// Read a `u32` value.
    #[inline]
    fn read_u32(&mut self) -> Option<u32> {
        self.read_pod::<u32>()
    }

    /// Read a `u64` value.
    #[inline]
    fn read_u64(&mut self) -> Option<u64> {
        self.read_pod::<u64>()
    }

    /// Read a `u64` encoded as unsigned variable length little endian base 128
    /// value.
    ///
    /// The function returns the value read along with the number of bytes
    /// consumed.
    fn read_u64_leb128(&mut self) -> Option<(u64, u8)> {
        let mut shift = 0;
        let mut value = 0u64;
        while let Some(bytes) = self.read_slice(1) {
            if let [byte] = bytes {
                value |= ((byte & 0b0111_1111) as u64) << shift;
                shift += 7;
                if (byte & 0b1000_0000) == 0 {
                    return Some((value, shift / 7))
                }
            } else {
                unreachable!()
            }
        }
        None
    }

    /// Read a `u64` encoded as signed variable length little endian base 128
    /// value.
    ///
    /// The function returns the value read along with the number of bytes
    /// consumed.
    fn read_i64_leb128(&mut self) -> Option<(i64, u8)> {
        let (value, shift) = self.read_u64_leb128()?;
        let sign_bits = u64::BITS as u8 - shift * 7;
        let value = ((value as i64) << sign_bits) >> sign_bits;
        Some((value, shift))
    }
}

impl<'data> ReadRaw<'data> for &'data [u8] {
    #[inline]
    fn ensure(&self, len: usize) -> Option<()> {
        if len > self.len() {
            return None
        }
        Some(())
    }

    #[inline]
    fn align(&mut self, align_to: usize) -> Option<()> {
        let offset = self.as_ptr().align_offset(align_to);
        let _slice = self.read_slice(offset)?;
        Some(())
    }

    #[inline]
    fn read_slice(&mut self, len: usize) -> Option<&'data [u8]> {
        self.ensure(len)?;
        let (a, b) = self.split_at(len);
        *self = b;
        Some(a)
    }

    #[inline]
    fn read_cstr(&mut self) -> Option<&'data CStr> {
        let idx = self.iter().position(|byte| *byte == b'\0')?;
        CStr::from_bytes_with_nul(self.read_slice(idx + 1)?).ok()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::cmp::Ordering;


    /// Check whether an iterator represents a sorted sequence.
    // Copy of iterator::is_sorted_by used while it is still unstable.
    pub fn is_sorted_by<I, F>(mut iter: I, compare: F) -> bool
    where
        I: Iterator,
        F: FnMut(&I::Item, &I::Item) -> Option<Ordering>,
    {
        #[inline]
        fn check<'a, T>(
            last: &'a mut T,
            mut compare: impl FnMut(&T, &T) -> Option<Ordering> + 'a,
        ) -> impl FnMut(T) -> bool + 'a {
            move |curr| {
                if let Some(Ordering::Greater) | None = compare(last, &curr) {
                    return false
                }
                *last = curr;
                true
            }
        }

        let mut last = match iter.next() {
            Some(e) => e,
            None => return true,
        };

        iter.all(check(&mut last, compare))
    }

    /// Check whether an iterator represents a sorted sequence.
    #[inline]
    fn is_sorted<I>(iter: I) -> bool
    where
        I: Iterator,
        I::Item: PartialOrd,
    {
        is_sorted_by(iter, PartialOrd::partial_cmp)
    }


    /// Make sure that we can detect sorted slices.
    #[test]
    fn sorted_check() {
        assert!(is_sorted([1, 5, 6].iter()));
        assert!(!is_sorted([1, 5, 6, 0].iter()));
    }

    /// Check that we can reorder elements in an array as expected.
    #[test]
    fn array_reordering() {
        let mut array = vec![];
        reorder::<usize, ()>(&mut array, vec![]);

        let mut array = vec![8];
        reorder(&mut array, vec![((), 0)]);
        assert_eq!(array, vec![8]);

        let mut array = vec![8, 1, 4, 0, 3];
        reorder(
            &mut array,
            [4, 1, 3, 0, 2].into_iter().map(|x| ((), x)).collect(),
        );
        assert_eq!(array, vec![0, 1, 3, 4, 8]);
    }

    /// Check that `with_ordered_elems` works as it should.
    #[test]
    fn with_element_ordering() {
        let vec = vec![5u8, 0, 1, 99, 6, 2];
        let result = with_ordered_elems(
            &vec,
            |x: &mut Vec<u8>| x.as_mut_slice(),
            |iter| {
                let vec = iter.collect::<Vec<_>>();
                assert!(is_sorted(vec.iter()));
                Result::<_, ()>::Ok(vec.into_iter().map(|x| x + 2).collect::<Vec<_>>())
            },
        )
        .unwrap();
        assert_eq!(result, vec.into_iter().map(|x| x + 2).collect::<Vec<_>>());
    }

    /// Make sure that `[u8]::ensure` works as expected.
    #[test]
    fn u8_slice_len_ensurance() {
        let slice = [0u8; 0].as_slice();
        assert_eq!(slice.ensure(0), Some(()));
        assert_eq!(slice.ensure(1), None);

        let slice = [1u8].as_slice();
        assert_eq!(slice.ensure(0), Some(()));
        assert_eq!(slice.ensure(1), Some(()));
        assert_eq!(slice.ensure(2), None);
    }

    /// Check that we can align the read pointer on a `[u8]`.
    #[test]
    fn u8_slice_align() {
        let mut buffer = [0u8; 64];
        let ptr = buffer.as_mut_ptr();

        // Make sure that we have an aligned pointer to begin with.
        let aligned_ptr = match ptr.align_offset(align_of::<u64>()) {
            offset if offset < size_of::<u64>() => unsafe { ptr.add(offset) },
            _ => unreachable!(),
        };

        let aligned = unsafe { slice::from_raw_parts(aligned_ptr, 16) };
        let mut data = aligned;

        let () = data.align(1).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        let () = data.align(2).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        let () = data.align(4).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        let () = data.align(8).unwrap();
        assert_eq!(data.as_ptr(), aligned.as_ptr());

        // After this read we are unaligned again.
        let _byte = data.read_u8();

        // Nothing should happen when attempting to align to 1 byte
        // boundary.
        let () = data.align(1).unwrap();
        assert_eq!(data.as_ptr(), unsafe { aligned.as_ptr().add(1) });

        // But once we align to a four byte boundary we the pointer
        // should move.
        let () = data.align(4).unwrap();
        assert_eq!(data.as_ptr(), unsafe { aligned.as_ptr().add(4) });
    }

    /// Check that we can read various integers from a slice.
    #[test]
    fn pod_reading() {
        macro_rules! test {
            ($type:ty) => {{
                let max = <$type>::MAX.to_ne_bytes();
                let one = (1 as $type).to_ne_bytes();

                let mut data = Vec::new();
                let () = data.extend_from_slice(&max);
                let () = data.extend_from_slice(&one);
                let () = data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

                let mut raw = data.as_slice();
                let uword = raw.read_pod::<$type>().unwrap();
                assert_eq!(uword, <$type>::MAX);

                let uword = raw.read_pod::<$type>().unwrap();
                assert_eq!(uword, 1);
            }};
        }

        test!(i8);
        test!(u8);
        test!(i16);
        test!(u16);
        test!(i32);
        test!(u32);
        test!(i64);
        test!(u64);
        test!(i128);
        test!(u128);
    }

    /// Check that we can read references to `Pod`s.
    #[test]
    fn pod_ref_reading() {
        // This test assumes that `u64`'s required alignment is greater
        // than 1.
        assert!(align_of::<u64>() > 1, "{}", align_of::<u64>());

        let mut buffer = [0u8; 64];
        let ptr = buffer.as_mut_ptr();

        let aligned_ptr = match ptr.align_offset(align_of::<u64>()) {
            offset if offset < size_of::<u64>() => unsafe { ptr.add(offset) },
            _ => unreachable!(),
        };

        // Write some data at the aligned location so that we can read
        // it back.
        let () = unsafe { aligned_ptr.cast::<u64>().write(1337) };

        // We are sure that we have at least space for two `u64` (16
        // bytes) in the buffer, even after alignment.
        let mut slice = unsafe { slice::from_raw_parts(aligned_ptr, 16) };
        assert_eq!(slice.read_pod_ref::<u64>(), Some(&1337));

        // Make sure that we fail if there is insufficient space.
        let mut slice = unsafe { slice::from_raw_parts(aligned_ptr, 4) };
        assert_eq!(slice.read_pod_ref::<u64>(), None);

        // Now also try with an unaligned pointer. It is guaranteed to
        // be unaligned if we add a one byte offset.
        let mut slice = unsafe { slice::from_raw_parts(aligned_ptr.add(1), 15) };
        assert_eq!(slice.read_pod_ref::<u64>(), None);
    }

    /// Test reading of signed and unsigned 16 and 32 bit values against known
    /// results.
    #[test]
    fn word_reading() {
        let data = 0xf936857fu32.to_ne_bytes();
        assert_eq!(data.as_slice().read_u16().unwrap(), 0x857f);
        assert_eq!(data.as_slice().read_i16().unwrap(), -31361);
        assert_eq!(data.as_slice().read_u32().unwrap(), 0xf936857f);
        assert_eq!(data.as_slice().read_i32().unwrap(), -113867393);
    }

    /// Make sure that we can read leb128 encoded values.
    #[test]
    fn leb128_reading() {
        let data = [0xf4, 0xf3, 0x75];
        let (v, s) = data.as_slice().read_u64_leb128().unwrap();
        assert_eq!(v, 0x1d79f4);
        assert_eq!(s, 3);

        let (v, s) = data.as_slice().read_i64_leb128().unwrap();
        assert_eq!(v, -165388);
        assert_eq!(s, 3);
    }

    /// Check that we can read a NUL terminated string from a slice.
    #[test]
    fn cstr_reading() {
        let mut slice = b"abc\x001234".as_slice();

        let cstr = slice.read_cstr().unwrap();
        assert_eq!(cstr, CStr::from_bytes_with_nul(b"abc\0").unwrap());

        // No terminating NUL byte.
        let mut slice = b"abc".as_slice();
        assert_eq!(slice.read_cstr(), None);
    }

    /// Test that we correctly binary search for a lowest match.
    #[test]
    fn search_lowest_match() {
        fn test(f: impl Fn(&[u16], &u16) -> Option<usize>) {
            let data = [];
            assert_eq!(f(&data, &0), None);

            let data = [5];
            assert_eq!(f(&data, &0), None);
            assert_eq!(f(&data, &1), None);
            assert_eq!(f(&data, &4), None);
            assert_eq!(f(&data, &5), Some(0));
            assert_eq!(f(&data, &6), None);

            let data = [5, 5];
            assert_eq!(f(&data, &5), Some(0));

            let data = [5, 5, 5];
            assert_eq!(f(&data, &5), Some(0));

            let data = [5, 5, 5, 5];
            assert_eq!(f(&data, &5), Some(0));

            let data = [4, 5, 5, 5, 5];
            assert_eq!(f(&data, &5), Some(1));

            let data = [1, 4, 42, 43, 99];
            assert_eq!(f(&data, &0), None);
            assert_eq!(f(&data, &1), Some(0));
            assert_eq!(f(&data, &4), Some(1));
            assert_eq!(f(&data, &5), None);
            assert_eq!(f(&data, &41), None);
            assert_eq!(f(&data, &98), None);
            assert_eq!(f(&data, &99), Some(4));
            assert_eq!(f(&data, &100), None);
            assert_eq!(f(&data, &1337), None);
        }

        test(find_lowest_match);
        test(|data, item| find_lowest_match_by_key(data, item, |elem| *elem));
    }

    /// Test that we correctly binary search for a match or a lower bound.
    #[test]
    fn search_match_or_lower_bound() {
        let data = [];
        assert_eq!(find_match_or_lower_bound(&data, &0), None);

        let data = [5];
        assert_eq!(find_match_or_lower_bound(&data, 0), None);
        assert_eq!(find_match_or_lower_bound(&data, 1), None);
        assert_eq!(find_match_or_lower_bound(&data, 4), None);
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));
        assert_eq!(find_match_or_lower_bound(&data, 6), Some(0));

        let data = [5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));

        let data = [5, 5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));

        let data = [5, 5, 5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(0));

        let data = [4, 5, 5, 5, 5];
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(1));

        let data = [1, 4, 42, 43, 99];
        assert_eq!(find_match_or_lower_bound(&data, 0), None);
        assert_eq!(find_match_or_lower_bound(&data, 1), Some(0));
        assert_eq!(find_match_or_lower_bound(&data, 4), Some(1));
        assert_eq!(find_match_or_lower_bound(&data, 5), Some(1));
        assert_eq!(find_match_or_lower_bound(&data, 41), Some(1));
        assert_eq!(find_match_or_lower_bound(&data, 98), Some(3));
        assert_eq!(find_match_or_lower_bound(&data, 99), Some(4));
        assert_eq!(find_match_or_lower_bound(&data, 100), Some(4));
        assert_eq!(find_match_or_lower_bound(&data, 1337), Some(4));
    }
}
