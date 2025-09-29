use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::inspect::SymType;
use crate::symbolize::AddrCodeInfo;
use crate::util::find_match_or_lower_bound_by_key;
use crate::Addr;
use crate::IntSym;
use crate::Result;
use crate::SrcLang;
use crate::SymResolver;

pub const KALLSYMS: &str = "/proc/kallsyms";
const DFL_KSYM_CAP: usize = 200000;

#[derive(Debug)]
pub struct Ksym {
    pub addr: Addr,
    pub name: String,
}

impl<'ksym> From<&'ksym Ksym> for IntSym<'ksym> {
    fn from(other: &'ksym Ksym) -> Self {
        let Ksym { name, addr } = other;
        IntSym {
            name,
            addr: *addr,
            // There is no size information in kallsyms.
            size: None,
            // Kernel symbols don't carry any source code language
            // information.
            lang: SrcLang::Unknown,
        }
    }
}

/// The symbol resolver for /proc/kallsyms.
///
/// The users should provide the path of kallsyms, so you can provide
/// a copy from other devices.
pub struct KSymResolver {
    syms: Vec<Ksym>,
    sym_to_addr: RefCell<HashMap<&'static str, Addr>>,
    file_name: PathBuf,
}

impl KSymResolver {
    pub fn load_file_name(filename: PathBuf) -> Result<Self> {
        let f = File::open(&filename)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        let mut syms = Vec::with_capacity(DFL_KSYM_CAP);

        loop {
            let sz = reader.read_line(&mut line)?;
            if sz == 0 {
                break
            }
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 3 {
                break
            }
            let (addr, _symbol, func) = (tokens[0], tokens[1], tokens[2]);
            if let Ok(addr) = Addr::from_str_radix(addr, 16) {
                if addr == 0 {
                    line.truncate(0);
                    continue
                }
                let name = String::from(func);
                syms.push(Ksym { addr, name });
            }

            line.truncate(0);
        }

        syms.sort_by(|a, b| a.addr.cmp(&b.addr));

        let slf = Self {
            syms,
            sym_to_addr: RefCell::default(),
            file_name: filename,
        };
        Ok(slf)
    }

    fn ensure_sym_to_addr(&self) {
        if self.sym_to_addr.borrow().len() > 0 {
            return
        }
        let mut sym_to_addr = self.sym_to_addr.borrow_mut();
        for Ksym { name, addr } in self.syms.iter() {
            // Performance & lifetime hacking
            let name_static = unsafe { &*(name as *const String) };
            sym_to_addr.insert(name_static, *addr);
        }
    }

    fn find_ksym(&self, addr: Addr) -> Option<&Ksym> {
        find_match_or_lower_bound_by_key(&self.syms, addr, |ksym: &Ksym| ksym.addr)
            .and_then(|idx| self.syms.get(idx))
    }

    /// Retrieve the path to the kallsyms file used by this resolver.
    pub(crate) fn file_name(&self) -> &Path {
        &self.file_name
    }
}

impl SymResolver for KSymResolver {
    fn find_sym(&self, addr: Addr) -> Result<Option<IntSym<'_>>> {
        let sym = self.find_ksym(addr).map(IntSym::from);
        Ok(sym)
    }

    fn find_addr(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymInfo>> {
        if let SymType::Variable = opts.sym_type {
            return Ok(Vec::new())
        }
        let () = self.ensure_sym_to_addr();

        let sym_to_addr = self.sym_to_addr.borrow();
        if let Some(addr) = sym_to_addr.get(name) {
            Ok(vec![SymInfo {
                name: name.to_string(),
                addr: *addr,
                size: 0,
                sym_type: SymType::Function,
                file_offset: 0,
                obj_file_name: None,
            }])
        } else {
            Ok(Vec::new())
        }
    }

    fn find_code_info(&self, _addr: Addr, _inlined_fns: bool) -> Result<Option<AddrCodeInfo>> {
        Ok(None)
    }

    fn addr_file_off(&self, _addr: Addr) -> Option<u64> {
        None
    }
}

impl Debug for KSymResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "KSymResolver")
    }
}


/// Cache of KSymResolver.
///
/// It returns the same instance if path is the same.
#[derive(Debug)]
pub struct KSymCache {
    resolvers: RefCell<HashMap<PathBuf, Rc<KSymResolver>>>,
}

impl KSymCache {
    pub fn new() -> KSymCache {
        KSymCache {
            resolvers: RefCell::new(HashMap::new()),
        }
    }

    /// Find an instance of KSymResolver from the cache or create a new one.
    pub fn get_resolver(&self, path: &Path) -> Result<Rc<KSymResolver>> {
        let mut resolvers = self.resolvers.borrow_mut();
        if let Some(resolver) = resolvers.get(path) {
            return Ok(resolver.clone())
        }

        let resolver = KSymResolver::load_file_name(path.to_path_buf())?;
        let resolver = Rc::new(resolver);
        resolvers.insert(path.to_path_buf(), resolver.clone());
        Ok(resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    use crate::ErrorKind;


    /// Check that we can use a `KSymResolver` to find symbols.
    #[test]
    fn ksym_resolver_load_find() {
        let result = KSymResolver::load_file_name(PathBuf::from(KALLSYMS));
        let resolver = match result {
            Ok(resolver) => resolver,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => panic!("failed to instantiate KSymResolver: {err}"),
        };

        assert!(
            resolver.syms.len() > 10000,
            "kallsyms seems to be unavailable or with all 0 addresses. (Check {KALLSYMS})"
        );

        // Find the address of the symbol placed at the middle
        let sym = &resolver.syms[resolver.syms.len() / 2];
        let addr = sym.addr;
        let name = sym.name.clone();
        let found = resolver.find_sym(addr).unwrap().unwrap();
        assert_eq!(found.name, name);

        let found = resolver.find_sym(addr + 1).unwrap().unwrap();
        assert_eq!(found.name, name);

        // 0 is an invalid address.  We remove all symbols with 0 as
        // thier address from the list.
        assert!(resolver.find_sym(0).unwrap().is_none());

        // Find the address of the last symbol
        let sym = &resolver.syms.last().unwrap();
        let addr = sym.addr;
        let name = sym.name.clone();
        let found = resolver.find_sym(addr).unwrap().unwrap();
        assert_eq!(found.name, name);

        let found = resolver.find_sym(addr + 1).unwrap().unwrap();
        assert_eq!(found.name, name);

        // Find the symbol placed at the one third
        let sym = &resolver.syms[resolver.syms.len() / 3];
        let addr = sym.addr;
        let name = sym.name.clone();
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymType::Function,
        };
        let found = resolver.find_addr(&name, &opts).unwrap();
        assert!(found.iter().any(|x| x.addr == addr));
    }

    #[test]
    fn ksym_cache() {
        let kallsyms = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("kallsyms");
        let cache = KSymCache::new();
        let resolver = cache.get_resolver(&kallsyms);
        let resolver1 = cache.get_resolver(&kallsyms);
        assert!(resolver.is_ok());
        assert!(resolver1.is_ok());
    }

    #[test]
    fn find_ksym() {
        let resolver = KSymResolver {
            syms: vec![
                Ksym {
                    addr: 0x123,
                    name: "1".to_string(),
                },
                Ksym {
                    addr: 0x123,
                    name: "1.5".to_string(),
                },
                Ksym {
                    addr: 0x1234,
                    name: "2".to_string(),
                },
                Ksym {
                    addr: 0x12345,
                    name: "3".to_string(),
                },
            ],
            sym_to_addr: RefCell::default(),
            file_name: PathBuf::new(),
        };

        // The address is less than the smallest address of all symbols.
        assert!(resolver.find_ksym(1).is_none());

        // The address match symbols exactly (the first address.)
        let sym = resolver.find_ksym(0x123).unwrap();
        assert_eq!(sym.addr, 0x123);
        assert_eq!(sym.name, "1");

        // The address is in between two symbols (the first address.)
        let sym = resolver.find_ksym(0x124).unwrap();
        assert_eq!(sym.addr, 0x123);
        assert_eq!(sym.name, "1.5");

        // The address match symbols exactly.
        let sym = resolver.find_ksym(0x1234).unwrap();
        assert_eq!(sym.addr, 0x1234);
        assert_eq!(sym.name, "2");

        // The address is in between two symbols.
        let sym = resolver.find_ksym(0x1235).unwrap();
        assert_eq!(sym.addr, 0x1234);
        assert_eq!(sym.name, "2");

        // The address match symbols exactly (the biggest address.)
        let sym = resolver.find_ksym(0x12345).unwrap();
        assert_eq!(sym.addr, 0x12345);
        assert_eq!(sym.name, "3");

        // The address is bigger than the biggest address of all symbols.
        let sym = resolver.find_ksym(0x1234568).unwrap();
        assert_eq!(sym.addr, 0x12345);
        assert_eq!(sym.name, "3");
    }
}
