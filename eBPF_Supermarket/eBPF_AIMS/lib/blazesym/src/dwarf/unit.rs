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

use super::function::Function;
use super::function::Functions;
use super::lazy::LazyCell;
use super::lines::Lines;
use super::location::Location;
use super::location::LocationRangeUnitIter;
use super::reader::R;


pub(super) struct UnitRange {
    pub unit_id: usize,
    pub max_end: u64,
    pub range: gimli::Range,
}


pub(super) struct Unit<'dwarf> {
    dw_unit: gimli::Unit<R<'dwarf>>,
    lang: Option<gimli::DwLang>,
    lines: LazyCell<Result<Lines<'dwarf>, gimli::Error>>,
    funcs: LazyCell<Result<Functions<'dwarf>, gimli::Error>>,
}

impl<'dwarf> Unit<'dwarf> {
    pub(super) fn new(
        unit: gimli::Unit<R<'dwarf>>,
        lang: Option<gimli::DwLang>,
        lines: LazyCell<Result<Lines<'dwarf>, gimli::Error>>,
    ) -> Self {
        Self {
            dw_unit: unit,
            lang,
            lines,
            funcs: LazyCell::new(),
        }
    }

    #[cfg(test)]
    #[cfg(feature = "nightly")]
    pub(super) fn parse_functions<'unit>(
        &'unit self,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<&'unit Functions<'dwarf>, gimli::Error> {
        let unit = &self.dw_unit;
        let functions = self.parse_functions_dwarf_and_unit(unit, sections)?;
        Ok(functions)
    }

    #[cfg(test)]
    #[cfg(feature = "nightly")]
    pub(super) fn parse_inlined_functions<'unit>(
        &'unit self,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<&'unit Functions<'dwarf>, gimli::Error> {
        let unit = &self.dw_unit;
        let functions = self
            .funcs
            .borrow_with(|| {
                let funcs = Functions::parse(unit, sections)?;
                let () = funcs.parse_inlined_functions(unit, sections)?;
                Ok(funcs)
            })
            .as_ref()
            .map_err(gimli::Error::clone)?;
        Ok(functions)
    }

    pub(super) fn parse_lines(
        &self,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<Option<&Lines<'dwarf>>, gimli::Error> {
        // NB: line information is always stored in the main debug file so this does not need
        // to handle DWOs.
        let ilnp = match self.dw_unit.line_program {
            Some(ref ilnp) => ilnp,
            None => return Ok(None),
        };
        self.lines
            .borrow_with(|| Lines::parse(&self.dw_unit, ilnp.clone(), sections))
            .as_ref()
            .map(Some)
            .map_err(gimli::Error::clone)
    }

    pub(super) fn find_location(
        &self,
        probe: u64,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<Option<Location<'_>>, gimli::Error> {
        if let Some(mut iter) = LocationRangeUnitIter::new(self, sections, probe, probe + 1)? {
            match iter.next() {
                None => Ok(None),
                Some((_addr, _len, loc)) => Ok(Some(loc)),
            }
        } else {
            Ok(None)
        }
    }

    fn parse_functions_dwarf_and_unit(
        &self,
        unit: &gimli::Unit<R<'dwarf>>,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<&Functions<'dwarf>, gimli::Error> {
        self.funcs
            .borrow_with(|| Functions::parse(unit, sections))
            .as_ref()
            .map_err(gimli::Error::clone)
    }

    pub(super) fn find_function(
        &self,
        probe: u64,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<Option<&Function<'dwarf>>, gimli::Error> {
        let unit = &self.dw_unit;
        let functions = self.parse_functions_dwarf_and_unit(unit, sections)?;
        let function = match functions.find_address(probe) {
            Some(address) => {
                let function_index = functions.addresses[address].function;
                let function = &functions.functions[function_index];
                Some(function)
            }
            None => None,
        };
        Ok(function)
    }

    pub(super) fn find_name<'slf>(
        &'slf self,
        name: &str,
        sections: &gimli::Dwarf<R<'dwarf>>,
    ) -> Result<Option<&'slf Function<'dwarf>>, gimli::Error> {
        let unit = &self.dw_unit;
        let functions = self.parse_functions_dwarf_and_unit(unit, sections)?;
        for func in functions.functions.iter() {
            let name = Some(name.as_bytes());
            if func.name.as_ref().map(|r| r.slice()) == name {
                return Ok(Some(func))
            }
        }
        Ok(None)
    }

    /// Attempt to retrieve the compilation unit's source code language.
    #[inline]
    pub(super) fn dw_unit(&self) -> &gimli::Unit<R<'dwarf>> {
        &self.dw_unit
    }

    /// Attempt to retrieve the compilation unit's source code language.
    #[inline]
    pub(super) fn language(&self) -> Option<gimli::DwLang> {
        self.lang
    }
}
