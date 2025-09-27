// Based on gimli-rs/addr2line (https://github.com/gimli-rs/addr2line):
// > Copyright (c) 2016-2018 The gimli Developers
// >
// > Permission is hereby granted, free of charge, to any
// > person obtaining a copy of this software and associated
// > documentation files (the "Software"), to deal in the
// > Software without restriction, including without
// > limitation the rights to use, copy, modify, merge,
// > publish, distribute, sublicense, and/or sell copies of
// > the Software, and to permit persons to whom the Software
// > is furnished to do so, subject to the following
// > conditions:
// >
// > The above copyright notice and this permission notice
// > shall be included in all copies or substantial portions
// > of the Software.
// >
// > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// > ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// > TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// > PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// > SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// > CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// > OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// > IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// > DEALINGS IN THE SOFTWARE.

use core::cell::UnsafeCell;

pub struct LazyCell<T> {
    contents: UnsafeCell<Option<T>>,
}
impl<T> LazyCell<T> {
    pub fn new() -> LazyCell<T> {
        LazyCell {
            contents: UnsafeCell::new(None),
        }
    }

    pub fn borrow_with(&self, closure: impl FnOnce() -> T) -> &T {
        // First check if we're already initialized...
        let ptr = self.contents.get();
        if let Some(val) = unsafe { &*ptr } {
            return val
        }
        // Note that while we're executing `closure` our `borrow_with` may
        // be called recursively. This means we need to check again after
        // the closure has executed. For that we use the `get_or_insert`
        // method which will only perform mutation if we aren't already
        // `Some`.
        let val = closure();
        unsafe { (*ptr).get_or_insert(val) }
    }
}
