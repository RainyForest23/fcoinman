pub mod accounts;
pub mod files;
pub mod logs;
pub mod network;
pub mod persistence;
pub mod process;
pub mod tools;

use crate::finding::Finding;

pub trait Scanner {
    fn name(&self) -> &str;
    fn scan(&self) -> Vec<Finding>;
}
