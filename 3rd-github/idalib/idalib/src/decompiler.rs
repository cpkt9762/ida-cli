use std::ffi::CString;
use std::fmt;
use std::marker::PhantomData;

use crate::ffi::hexrays::{
    addr_range, cblock_iter, cblock_t, cfunc_t, cfuncptr_t, cinsn_t, eamap_result,
    idalib_hexrays_cblock_iter, idalib_hexrays_cblock_iter_next, idalib_hexrays_cblock_len,
    idalib_hexrays_cfunc_find_stmts_at, idalib_hexrays_cfunc_get_stmt_bounds,
    idalib_hexrays_cfunc_has_eamap, idalib_hexrays_cfunc_pseudocode,
    idalib_hexrays_cfunc_pseudocode_plain_lines, idalib_hexrays_cfunc_pseudocode_tagged_lines,
    idalib_hexrays_cfunc_treeitem_ea, idalib_hexrays_cfuncptr_inner, idalib_hexrays_cinsn_ea,
    idalib_hexrays_cinsn_op, idalib_hexrays_cinsn_print, idalib_hexrays_eamap_result_len,
    idalib_hexrays_eamap_result_next, idalib_hexrays_rename_lvar,
    idalib_hexrays_set_decompiler_comment, idalib_hexrays_set_lvar_type,
};
use crate::ffi::{BADADDR, from_ea};
use crate::idb::IDB;
use crate::{Address, IDAError};

pub use crate::ffi::hexrays::{HexRaysError, HexRaysErrorCode};

/// Address range covered by a decompiled statement
#[derive(Debug, Clone, Copy)]
pub struct AddressRange {
    pub start: Address,
    pub end: Address,
}

impl From<addr_range> for AddressRange {
    fn from(r: addr_range) -> Self {
        Self {
            start: r.start,
            end: r.end,
        }
    }
}

pub struct CFunction<'a> {
    ptr: *mut cfunc_t,
    _obj: cxx::UniquePtr<cfuncptr_t>,
    _marker: PhantomData<&'a IDB>,
}

pub struct CBlock<'a> {
    ptr: *mut cblock_t,
    func_ptr: *mut cfunc_t,
    _marker: PhantomData<&'a ()>,
}

pub struct CBlockIter<'a> {
    it: cxx::UniquePtr<cblock_iter>,
    func_ptr: *mut cfunc_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for CBlockIter<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_cblock_iter_next(self.it.pin_mut()) };

        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                func_ptr: self.func_ptr,
                _marker: PhantomData,
            })
        }
    }
}

pub struct CInsn<'a> {
    ptr: *mut cinsn_t,
    func_ptr: *mut cfunc_t,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CInsn<'a> {
    /// Get the address associated with this statement.
    pub fn address(&self) -> Address {
        unsafe { idalib_hexrays_cinsn_ea(self.ptr) }
    }

    /// Get the opcode/type of this statement (cit_* constant).
    pub fn opcode(&self) -> i32 {
        unsafe { idalib_hexrays_cinsn_op(self.ptr).0 }
    }

    /// Get the address range covered by this statement.
    pub fn bounds(&self) -> Option<AddressRange> {
        let mut out = addr_range { start: 0, end: 0 };
        let ok = unsafe { idalib_hexrays_cfunc_get_stmt_bounds(self.func_ptr, self.ptr, &mut out) };
        if ok { Some(out.into()) } else { None }
    }
}

impl fmt::Display for CInsn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = unsafe { idalib_hexrays_cinsn_print(self.ptr, self.func_ptr) };
        write!(f, "{}", text)
    }
}

/// Iterator over statements at an address
pub struct StatementsAtAddr<'a> {
    result: cxx::UniquePtr<eamap_result>,
    func: &'a CFunction<'a>,
}

impl<'a> Iterator for StatementsAtAddr<'a> {
    type Item = CInsn<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = unsafe { idalib_hexrays_eamap_result_next(self.result.pin_mut()) };
        if ptr.is_null() {
            None
        } else {
            Some(CInsn {
                ptr,
                func_ptr: self.func.ptr,
                _marker: PhantomData,
            })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { idalib_hexrays_eamap_result_len(self.result.as_ref().unwrap()) };
        (0, Some(len))
    }
}

impl<'a> CFunction<'a> {
    pub(crate) fn new(obj: cxx::UniquePtr<cfuncptr_t>) -> Option<Self> {
        let ptr = unsafe { idalib_hexrays_cfuncptr_inner(obj.as_ref().expect("valid pointer")) };

        if ptr.is_null() {
            return None;
        }

        Some(Self {
            ptr,
            _obj: obj,
            _marker: PhantomData,
        })
    }

    /// Get the full pseudocode for this function as a string.
    pub fn pseudocode(&self) -> String {
        unsafe { idalib_hexrays_cfunc_pseudocode(self.ptr) }
    }

    /// The pseudocode, one entry per line, with the color tags removed.
    ///
    /// Same lines as [`CFunction::pseudocode`], cleaned with the same
    /// `tag_remove` call.
    pub fn pseudocode_plain_lines(&self) -> Result<Vec<String>, IDAError> {
        unsafe { idalib_hexrays_cfunc_pseudocode_plain_lines(self.ptr) }.map_err(IDAError::ffi)
    }

    /// The pseudocode, one entry per line, with the color tags kept.
    ///
    /// The tags carry Hex-Rays' `COLOR_ADDR` anchors: indices into the ctree
    /// items, resolved with [`CFunction::treeitem_address`].
    pub fn pseudocode_tagged_lines(&self) -> Result<Vec<String>, IDAError> {
        unsafe { idalib_hexrays_cfunc_pseudocode_tagged_lines(self.ptr) }.map_err(IDAError::ffi)
    }

    /// Address of the ctree item at `index` in `cfunc_t::treeitems`, the index
    /// a `COLOR_ADDR` anchor in the pseudocode refers to.
    ///
    /// `None` when the index is out of range or the item has no address.
    pub fn treeitem_address(&self, index: usize) -> Option<Address> {
        let ea = unsafe { idalib_hexrays_cfunc_treeitem_ea(self.ptr, index) };
        (ea != from_ea(BADADDR)).then_some(ea)
    }

    fn as_cfunc(&self) -> &cfunc_t {
        unsafe { self.ptr.as_ref().expect("valid pointer") }
    }

    /// Get the function body as a CBlock.
    pub fn body(&self) -> CBlock<'_> {
        let cf = self.as_cfunc();
        let ptr = unsafe { cf.body.__bindgen_anon_1.cblock };

        CBlock {
            ptr,
            func_ptr: self.ptr,
            _marker: PhantomData,
        }
    }

    /// Check if the address-to-statement mapping is available.
    /// This should be true after decompilation.
    pub fn has_eamap(&self) -> bool {
        unsafe { idalib_hexrays_cfunc_has_eamap(self.ptr) }
    }

    /// Find decompiled statements that correspond to a specific address.
    ///
    /// This is useful for finding what pseudocode corresponds to a basic block
    /// or specific instruction address.
    ///
    /// Returns `None` if no statements are found at the address.
    pub fn statements_at(&self, addr: Address) -> Option<StatementsAtAddr<'_>> {
        let result = unsafe { idalib_hexrays_cfunc_find_stmts_at(self.ptr, addr) };
        if result.is_null() {
            None
        } else {
            Some(StatementsAtAddr { result, func: self })
        }
    }

    /// Get pseudocode for statements in an address range (like a basic block).
    ///
    /// This collects all unique statements that cover any part of the given range
    /// and renders them as text.
    pub fn pseudocode_for_range(&self, start: Address, end: Address) -> Vec<String> {
        let mut seen_eas = std::collections::HashSet::new();
        let mut results = Vec::new();

        // Iterate through addresses in the range
        let mut addr = start;
        while addr < end {
            if let Some(stmts) = self.statements_at(addr) {
                for stmt in stmts {
                    let stmt_ea = stmt.address();
                    if seen_eas.insert(stmt_ea) {
                        results.push(stmt.to_string());
                    }
                }
            }
            addr += 1; // Move to next address
        }

        results
    }
}

impl<'a> CBlock<'a> {
    pub fn iter(&self) -> CBlockIter<'_> {
        CBlockIter {
            it: unsafe { idalib_hexrays_cblock_iter(self.ptr) },
            func_ptr: self.func_ptr,
            _marker: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        unsafe { idalib_hexrays_cblock_len(self.ptr) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Rename a local variable in a decompiled function by name.
pub fn rename_lvar(
    func_ea: Address,
    old_name: impl AsRef<str>,
    new_name: impl AsRef<str>,
) -> Option<()> {
    let old = CString::new(old_name.as_ref()).ok()?;
    let new = CString::new(new_name.as_ref()).ok()?;
    unsafe { idalib_hexrays_rename_lvar(func_ea.into(), old.as_ptr(), new.as_ptr()) }.then_some(())
}

/// Set the type of a local variable in a decompiled function.
pub fn set_lvar_type(
    func_ea: Address,
    lvar_name: impl AsRef<str>,
    type_str: impl AsRef<str>,
) -> Option<()> {
    let name = CString::new(lvar_name.as_ref()).ok()?;
    let ty = CString::new(type_str.as_ref()).ok()?;
    unsafe { idalib_hexrays_set_lvar_type(func_ea.into(), name.as_ptr(), ty.as_ptr()) }.then_some(())
}

/// Set a comment in decompiled pseudocode. itp=69 (ITP_SEMI) for line-end comments.
/// Empty comment string clears the comment.
pub fn set_decompiler_comment(
    func_ea: Address,
    addr: Address,
    itp: i32,
    comment: impl AsRef<str>,
) -> Option<()> {
    let cmt = CString::new(comment.as_ref()).ok()?;
    unsafe { idalib_hexrays_set_decompiler_comment(func_ea.into(), addr.into(), itp.into(), cmt.as_ptr()) }
        .then_some(())
}
