// Suppress historical clippy lints that predate the -D warnings CI policy.
// These are style suggestions, not correctness issues. Fix incrementally.
#![allow(
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::collapsible_str_replace,
    clippy::derivable_impls,
    clippy::empty_line_after_doc_comments,
    clippy::extend_with_drain,
    clippy::field_reassign_with_default,
    clippy::for_kv_map,
    clippy::implicit_saturating_sub,
    clippy::io_other_error,
    clippy::items_after_test_module,
    clippy::large_enum_variant,
    clippy::len_without_is_empty,
    clippy::len_zero,
    clippy::let_and_return,
    clippy::manual_clamp,
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of,
    clippy::manual_range_contains,
    clippy::manual_range_patterns,
    clippy::manual_split_once,
    clippy::map_flatten,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_range_loop,
    clippy::needless_return,
    clippy::needless_update,
    clippy::new_without_default,
    clippy::redundant_closure,
    clippy::redundant_field_names,
    clippy::redundant_guards,
    clippy::redundant_locals,
    clippy::should_implement_trait,
    clippy::single_match,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_get_then_check,
    clippy::unnecessary_lazy_evaluations,
    clippy::unnecessary_map_or,
    clippy::unnecessary_mut_passed,
    clippy::useless_format,
    clippy::vec_init_then_push
)]

pub mod api;
pub mod app;
pub mod common;
pub mod config;
pub mod derp;
pub mod dns;
pub mod plugin;
pub mod proxy;
pub mod router;
