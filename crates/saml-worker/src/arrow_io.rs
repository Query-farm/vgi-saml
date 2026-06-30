//! Arrow boundary helpers shared across the SAML scalar/table functions.
//!
//! The worker is a thin adapter: it reads a `BLOB`/`VARCHAR` input cell into
//! bytes, hands them to the pure `saml-core` engine, and marshals the engine's
//! typed output back into Arrow `STRUCT` / `LIST` / `TIMESTAMPTZ` columns. The
//! `STRUCT` field sets are defined once here so `on_bind` and `process` agree
//! exactly (a mismatch makes DuckDB reject the batch).

use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef, TimestampMicrosecondArray};

use arrow_schema::{DataType, Field, TimeUnit};
use vgi_rpc::{Result, RpcError};

/// The `TIMESTAMPTZ` Arrow type the worker emits (microseconds, UTC).
pub fn ts_type() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
}

/// Build a UTC `TIMESTAMPTZ` array from epoch-microsecond options.
pub fn ts_array(vals: Vec<Option<i64>>) -> ArrayRef {
    Arc::new(TimestampMicrosecondArray::from(vals).with_timezone("UTC"))
}

/// `LIST(VARCHAR)` element type — the element field is `item`/nullable and MUST
/// match between the declared schema and the built array.
pub fn list_varchar_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

/// Read a `BLOB` (`Binary`/`LargeBinary`) or `VARCHAR` (`Utf8`/`LargeUtf8`)
/// input cell at `row` as raw bytes, or `None` if the cell is null. Errors only
/// on a genuinely wrong column type.
pub fn input_bytes(col: &ArrayRef, row: usize) -> Result<Option<Vec<u8>>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Binary => col.as_binary::<i32>().value(row).to_vec(),
        DataType::LargeBinary => col.as_binary::<i64>().value(row).to_vec(),
        DataType::Utf8 => col.as_string::<i32>().value(row).as_bytes().to_vec(),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row).as_bytes().to_vec(),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a BLOB or VARCHAR SAML message, got {other:?}"
            )))
        }
    }))
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use arrow_array::builder::BinaryBuilder;
    use arrow_array::RecordBatch;
    use arrow_schema::{Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// A single-column `BLOB` input batch from raw message bytes (`None` = NULL).
    pub fn blob_batch(rows: &[Option<&[u8]>]) -> RecordBatch {
        let mut b = BinaryBuilder::new();
        for r in rows {
            match r {
                Some(s) => b.append_value(s),
                None => b.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(b.finish());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "msg",
            arr.data_type().clone(),
            true,
        )]));
        RecordBatch::try_new(schema, vec![arr]).unwrap()
    }

    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
            copy_from: None,
        }
    }

    /// Run a scalar over a one-column BLOB batch, returning the result column.
    pub fn run_scalar_blob<F: ScalarFunction>(f: &F, rows: &[Option<&[u8]>]) -> Result<ArrayRef> {
        let batch = blob_batch(rows);
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema.clone(), Arguments::default());
        Ok(f.process(&params, &batch)?.column(0).clone())
    }

    /// The declared output `DataType` from `on_bind`.
    pub fn bound_type<F: ScalarFunction>(f: &F) -> DataType {
        let bound = f.on_bind(&BindParams::default()).unwrap();
        bound.output_schema.field(0).data_type().clone()
    }
}
