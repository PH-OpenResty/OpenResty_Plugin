CREATE DATABASE IF NOT EXISTS scdn;
CREATE TABLE IF NOT EXISTS scdn.logs
(
 event_id FixedString(64), timestamp DateTime64(3, 'UTC'), node LowCardinality(String),
 source LowCardinality(String), kind LowCardinality(String), path String, generation String,
 offset UInt64, end_offset UInt64, raw_base64 String, terminated UInt8, fragment UInt8,
 archive UInt8, message String, format LowCardinality(String), fields_json String, normalized_json String,
 INDEX by_timestamp timestamp TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree
PARTITION BY cityHash64(node) % 16 ORDER BY (node, event_id);
CREATE VIEW IF NOT EXISTS scdn.events AS SELECT * FROM scdn.logs FINAL;
CREATE VIEW IF NOT EXISTS scdn.access AS SELECT
 event_id,
 coalesce(parseDateTime64BestEffortOrNull(JSONExtractString(normalized_json, 'time'), 3, 'UTC'), timestamp) AS time,
 node,
 JSONExtract(normalized_json, 'site', 'String') AS site,
 JSONExtract(normalized_json, 'host', 'String') AS host,
 JSONExtract(normalized_json, 'ip', 'String') AS ip,
 JSONExtract(normalized_json, 'ip_family', 'UInt8') AS ip_family,
 JSONExtract(normalized_json, 'internal', 'UInt8') AS internal,
 JSONExtract(normalized_json, 'uri', 'String') AS uri,
 JSONExtract(normalized_json, 'method', 'String') AS method,
 JSONExtract(normalized_json, 'status', 'UInt16') AS status,
 JSONExtract(normalized_json, 'bytes', 'UInt64') AS bytes,
 JSONExtract(normalized_json, 'duration_ms', 'Float64') AS duration_ms,
 JSONExtract(normalized_json, 'origin_ms', 'Float64') AS origin_ms,
 JSONExtract(normalized_json, 'origin_seen', 'UInt8') AS origin_seen,
 JSONExtract(normalized_json, 'cache', 'String') AS cache,
 JSONExtract(normalized_json, 'cache_layer', 'String') AS cache_layer,
 JSONExtract(normalized_json, 'country', 'String') AS country,
 JSONExtract(normalized_json, 'asn', 'UInt32') AS asn,
 JSONExtract(normalized_json, 'asn_org', 'String') AS asn_org,
 JSONExtract(normalized_json, 'operator', 'String') AS operator,
 JSONExtract(normalized_json, 'protocol', 'String') AS protocol,
 JSONExtract(normalized_json, 'blocked', 'UInt8') AS blocked,
 JSONExtract(normalized_json, 'block_reason', 'String') AS block_reason,
 JSONExtract(normalized_json, 'request_id', 'String') AS request_id
FROM scdn.logs FINAL WHERE kind='access' AND normalized_json!='';
CREATE VIEW IF NOT EXISTS scdn.bans AS SELECT
 event_id,
 fromUnixTimestamp64Milli(toInt64OrZero(JSONExtractString(normalized_json, 'time_ms'))) AS time,
 node,
 JSONExtract(normalized_json, 'ip', 'String') AS ip,
 JSONExtract(normalized_json, 'internal', 'UInt8') AS internal,
 JSONExtract(normalized_json, 'ban_id', 'String') AS ban_id,
 JSONExtract(normalized_json, 'scope', 'String') AS scope,
 JSONExtract(normalized_json, 'layer', 'UInt8') AS layer,
 JSONExtract(normalized_json, 'action', 'String') AS action,
 JSONExtract(normalized_json, 'source', 'String') AS source,
 JSONExtract(normalized_json, 'reason', 'String') AS reason,
 JSONExtract(normalized_json, 'origin', 'String') AS origin,
 JSONExtract(normalized_json, 'applied', 'UInt8') AS applied
FROM scdn.logs FINAL WHERE kind='ban' AND normalized_json!='';
CREATE VIEW IF NOT EXISTS scdn.node_samples AS SELECT
 fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')) AS time,
 node,
 JSONExtract(fields_json, 'sync_ok', 'Nullable(UInt8)') AS sync_ok,
 JSONExtract(fields_json, 'sync_sequence', 'String') AS sync_sequence,
 JSONExtract(fields_json, 'ban_ready', 'Nullable(UInt8)') AS ban_ready,
 JSONExtract(fields_json, 'active_bans', 'Nullable(UInt32)') AS active_bans,
 JSONExtract(fields_json, 'sites', 'Array(String)') AS sites,
 JSONExtract(fields_json, 'site_hosts', 'Array(String)') AS site_hosts,
 JSONExtract(fields_json, 'ban_records', 'String') AS ban_records,
 JSONExtract(fields_json, 'cpu_pct', 'Nullable(Float64)') AS cpu_pct,
 JSONExtract(fields_json, 'load1', 'Nullable(Float64)') AS load1,
 JSONExtract(fields_json, 'cpu_count', 'Nullable(UInt16)') AS cpu_count,
 JSONExtract(fields_json, 'mem_total', 'Nullable(UInt64)') AS mem_total,
 JSONExtract(fields_json, 'mem_available', 'Nullable(UInt64)') AS mem_available,
 JSONExtract(fields_json, 'mem_pct', 'Nullable(Float64)') AS mem_pct,
 JSONExtract(fields_json, 'net_rx', 'Nullable(UInt64)') AS net_rx,
 JSONExtract(fields_json, 'net_tx', 'Nullable(UInt64)') AS net_tx,
 JSONExtract(fields_json, 'rx_bps', 'Nullable(Float64)') AS rx_bps,
 JSONExtract(fields_json, 'tx_bps', 'Nullable(Float64)') AS tx_bps,
 JSONExtract(fields_json, 'cache_disk_total', 'Nullable(UInt64)') AS cache_disk_total,
 JSONExtract(fields_json, 'cache_disk_free', 'Nullable(UInt64)') AS cache_disk_free,
 JSONExtract(fields_json, 'cache_disk_pct', 'Nullable(Float64)') AS cache_disk_pct,
 JSONExtract(fields_json, 'api_web', 'Nullable(UInt64)') AS api_web,
 JSONExtract(fields_json, 'api_api', 'Nullable(UInt64)') AS api_api,
 JSONExtract(fields_json, 'api_ai', 'Nullable(UInt64)') AS api_ai,
 JSONExtract(fields_json, 'api_stream', 'Nullable(UInt64)') AS api_stream,
 JSONExtract(fields_json, 'api_grpc', 'Nullable(UInt64)') AS api_grpc,
 JSONExtract(fields_json, 'api_websocket', 'Nullable(UInt64)') AS api_websocket,
 JSONExtract(fields_json, 'native_requests', 'Nullable(UInt64)') AS native_requests,
 JSONExtract(fields_json, 'native_bytes', 'Nullable(UInt64)') AS native_bytes,
 JSONExtract(fields_json, 'source_clock_skew_ms', 'Int64') AS source_clock_skew_ms,
 JSONExtract(fields_json, 'kernel_drop_counter', 'Nullable(UInt64)') AS kernel_drop_counter,
 JSONExtract(fields_json, 'kernel_drop_delta', 'Nullable(UInt64)') AS kernel_drop_delta,
 JSONExtract(fields_json, 'kernel_drop_pps', 'Nullable(Float64)') AS kernel_drop_pps,
 JSONExtractRaw(fields_json, 'nginx_stats') AS nginx_stats,
 fields_json AS raw_sample
FROM scdn.logs FINAL WHERE kind='metrics' AND format='json';
CREATE TABLE IF NOT EXISTS scdn.node_inventory
(node String, address String, role String, enabled UInt8)
ENGINE = ReplacingMergeTree ORDER BY node;
CREATE VIEW IF NOT EXISTS scdn.collection_health AS SELECT
 fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')) AS time, node, 'direct' AS mode,
 JSONExtract(fields_json, 'collection', 'success', 'UInt8') AS success,
 JSONExtract(fields_json, 'collection', 'inserted', 'UInt64') AS inserted,
 JSONExtract(fields_json, 'collection', 'invalid', 'UInt64') AS invalid,
 JSONExtract(fields_json, 'collection', 'source_files', 'UInt32') AS source_files,
 JSONExtract(fields_json, 'collection', 'completed_files', 'UInt32') AS completed_files,
 JSONExtract(fields_json, 'collection', 'error', 'String') AS error
FROM scdn.logs FINAL WHERE kind='metrics' AND format='json';
CREATE VIEW IF NOT EXISTS scdn.network_samples AS SELECT
 fromUnixTimestamp64Milli(JSONExtractInt(fields_json, 'time')) AS time, node,
 JSONExtractRaw(fields_json, 'connections') AS connections,
 JSONExtractRaw(fields_json, 'network_protocols') AS host_protocols,
 JSONExtractRaw(fields_json, 'packets') AS packets,
 JSONExtractRaw(fields_json, 'packet_pps') AS packet_pps,
 JSONExtractRaw(fields_json, 'health') AS health
FROM scdn.logs FINAL WHERE kind='metrics' AND format='json';
