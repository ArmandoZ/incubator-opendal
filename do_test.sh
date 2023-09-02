set -x

cargo clippy

# RUST_LOG=debug 
RUST_LOG=debug RUST_BACKTRACE=full cargo test atomicdata --features services-atomicdata
