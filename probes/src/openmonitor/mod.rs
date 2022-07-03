use cty::c_char;

pub const PATHLEN: usize = 256;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct OpenPath {
    pub filename: [c_char; 16],
}

impl Default for OpenPath {
    fn default() -> OpenPath {
        OpenPath {
            filename: [0; 16],
        }
    }
}


