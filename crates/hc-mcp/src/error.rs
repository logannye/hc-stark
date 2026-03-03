use rmcp::model::CallToolResult;
use rmcp::model::Content;

pub fn tool_error(msg: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![Content::text(msg.to_string())])
}
