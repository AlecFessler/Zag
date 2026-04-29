//! Static frontend assets, embedded at compile time. We point at the
//! sibling `tools/callgraph/src/assets/` tree directly (build-time path)
//! so the in-development web UI doesn't have to be copied to live in two
//! places. When the user switches over to oracle_http they're seeing
//! the exact same JS/HTML they ran under the old server.

pub const index_html = @embedFile("assets/index.html");
pub const app_js = @embedFile("assets/app.js");
pub const trace_js = @embedFile("assets/trace.js");
pub const cytoscape_js = @embedFile("assets/cytoscape.min.js");
