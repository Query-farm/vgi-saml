//! Scalar functions exposed by the saml worker, registered under `saml.main`.

mod anomalies;
mod authn;
mod conditions;
mod decode;
mod fanout;
mod message_type;
mod signature;
mod transport;
mod well_formed;

#[cfg(test)]
mod tests;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(message_type::MessageType);
    worker.register_scalar(well_formed::WellFormed);
    worker.register_scalar(decode::Decode);
    worker.register_scalar(conditions::Conditions);
    worker.register_scalar(authn::AuthnFn);
    worker.register_scalar(signature::Signature);
    worker.register_scalar(anomalies::Anomalies);
    // Fan-outs as scalar LIST<STRUCT> (DuckDB table functions reject correlated
    // column args, so per-row fan-out over a column is scalar + UNNEST).
    worker.register_scalar(fanout::Attributes);
    worker.register_scalar(fanout::Signatures);
    worker.register_scalar(fanout::Assertions);
    worker.register_scalar(transport::B64Decode);
    worker.register_scalar(transport::Inflate);
    worker.register_scalar(transport::Unwrap);
}
