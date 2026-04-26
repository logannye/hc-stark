//! Simple recursive-descent parser for the hc-STARK DSL.
//!
//! Syntax (Rust-like):
//! ```text
//! fn main() {
//!     let x = 5;
//!     let y = x + 3;
//!     return y;
//! }
//! ```
//!
//! Supported constructs:
//! - `fn name(params) { body }`
//! - `let name = expr;`
//! - `name = expr;`
//! - `if expr { body } else { body }`
//! - `while expr { body }`
//! - `for name in start..end { body }`
//! - `return expr;`
//! - `assert_zero(expr);`
//! - `store(addr, value);`
//! - Expressions: literals, variables, binary ops (+, -, *, &, |, ^, <<, >>),
//!   unary ops (-, inv, sq), function calls, load(expr)

use super::frontend_ir::*;

/// Parse error with location information.
#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "parse error at position {}: {}",
            self.position, self.message
        )
    }
}

impl std::error::Error for ParseError {}

type ParseResult<T> = Result<T, ParseError>;

/// Tokenizer state.
struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    // Keywords
    Fn,
    Let,
    If,
    Else,
    While,
    For,
    In,
    Return,
    AssertZero,
    Store,
    Load,
    Inv,
    Sq,
    // Symbols
    LParen,
    RParen,
    LBrace,
    RBrace,
    Semicolon,
    Comma,
    Eq,
    EqEq,
    Lt,
    Plus,
    Minus,
    Star,
    Ampersand,
    Pipe,
    Caret,
    Shl,
    Shr,
    DotDot,
    // Values
    Number(u64),
    Ident(String),
    // End
    Eof,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let ch = self.input.as_bytes()[self.pos];
            if ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r' {
                self.pos += 1;
            } else if self.input[self.pos..].starts_with("//") {
                // Skip line comment
                while self.pos < self.input.len() && self.input.as_bytes()[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn peek(&mut self) -> ParseResult<Token> {
        let saved = self.pos;
        let tok = self.next_token()?;
        self.pos = saved;
        Ok(tok)
    }

    fn next_token(&mut self) -> ParseResult<Token> {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return Ok(Token::Eof);
        }

        let start = self.pos;
        let rest = &self.input[self.pos..];

        // Two-char tokens
        if rest.starts_with("==") {
            self.pos += 2;
            return Ok(Token::EqEq);
        }
        if rest.starts_with("<<") {
            self.pos += 2;
            return Ok(Token::Shl);
        }
        if rest.starts_with(">>") {
            self.pos += 2;
            return Ok(Token::Shr);
        }
        if rest.starts_with("..") {
            self.pos += 2;
            return Ok(Token::DotDot);
        }

        // Single-char tokens
        let ch = rest.as_bytes()[0];
        match ch {
            b'(' => {
                self.pos += 1;
                return Ok(Token::LParen);
            }
            b')' => {
                self.pos += 1;
                return Ok(Token::RParen);
            }
            b'{' => {
                self.pos += 1;
                return Ok(Token::LBrace);
            }
            b'}' => {
                self.pos += 1;
                return Ok(Token::RBrace);
            }
            b';' => {
                self.pos += 1;
                return Ok(Token::Semicolon);
            }
            b',' => {
                self.pos += 1;
                return Ok(Token::Comma);
            }
            b'=' => {
                self.pos += 1;
                return Ok(Token::Eq);
            }
            b'<' => {
                self.pos += 1;
                return Ok(Token::Lt);
            }
            b'+' => {
                self.pos += 1;
                return Ok(Token::Plus);
            }
            b'-' => {
                self.pos += 1;
                return Ok(Token::Minus);
            }
            b'*' => {
                self.pos += 1;
                return Ok(Token::Star);
            }
            b'&' => {
                self.pos += 1;
                return Ok(Token::Ampersand);
            }
            b'|' => {
                self.pos += 1;
                return Ok(Token::Pipe);
            }
            b'^' => {
                self.pos += 1;
                return Ok(Token::Caret);
            }
            _ => {}
        }

        // Number
        if ch.is_ascii_digit() {
            let end = self.pos
                + rest
                    .bytes()
                    .take_while(|b| b.is_ascii_digit() || *b == b'_')
                    .count();
            let num_str: String = self.input[self.pos..end]
                .chars()
                .filter(|c| *c != '_')
                .collect();
            self.pos = end;
            let n = num_str.parse::<u64>().map_err(|_| ParseError {
                message: format!("invalid number: {num_str}"),
                position: start,
            })?;
            return Ok(Token::Number(n));
        }

        // Identifier or keyword
        if ch.is_ascii_alphabetic() || ch == b'_' {
            let end = self.pos
                + rest
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    .count();
            let word = &self.input[self.pos..end];
            self.pos = end;
            return Ok(match word {
                "fn" => Token::Fn,
                "let" => Token::Let,
                "if" => Token::If,
                "else" => Token::Else,
                "while" => Token::While,
                "for" => Token::For,
                "in" => Token::In,
                "return" => Token::Return,
                "assert_zero" => Token::AssertZero,
                "store" => Token::Store,
                "load" => Token::Load,
                "inv" => Token::Inv,
                "sq" => Token::Sq,
                _ => Token::Ident(word.to_string()),
            });
        }

        Err(ParseError {
            message: format!("unexpected character: {}", ch as char),
            position: start,
        })
    }

    fn expect(&mut self, expected: Token) -> ParseResult<()> {
        let tok = self.next_token()?;
        if tok == expected {
            Ok(())
        } else {
            Err(ParseError {
                message: format!("expected {expected:?}, got {tok:?}"),
                position: self.pos,
            })
        }
    }

    fn expect_ident(&mut self) -> ParseResult<String> {
        match self.next_token()? {
            Token::Ident(name) => Ok(name),
            other => Err(ParseError {
                message: format!("expected identifier, got {other:?}"),
                position: self.pos,
            }),
        }
    }
}

/// Parse a complete program from source text.
pub fn parse(source: &str) -> ParseResult<IrProgram> {
    let mut lexer = Lexer::new(source);
    let mut functions = Vec::new();
    loop {
        let tok = lexer.peek()?;
        match tok {
            Token::Fn => functions.push(parse_function(&mut lexer)?),
            Token::Eof => break,
            other => {
                return Err(ParseError {
                    message: format!("expected 'fn' or end of input, got {other:?}"),
                    position: lexer.pos,
                });
            }
        }
    }
    Ok(IrProgram::new(functions))
}

fn parse_function(lexer: &mut Lexer) -> ParseResult<FnDef> {
    lexer.expect(Token::Fn)?;
    let name = lexer.expect_ident()?;
    lexer.expect(Token::LParen)?;
    let mut params = Vec::new();
    if lexer.peek()? != Token::RParen {
        params.push(lexer.expect_ident()?);
        while lexer.peek()? == Token::Comma {
            lexer.next_token()?; // consume comma
            params.push(lexer.expect_ident()?);
        }
    }
    lexer.expect(Token::RParen)?;
    lexer.expect(Token::LBrace)?;
    let body = parse_block(lexer)?;
    lexer.expect(Token::RBrace)?;
    Ok(FnDef { name, params, body })
}

fn parse_block(lexer: &mut Lexer) -> ParseResult<Vec<Stmt>> {
    let mut stmts = Vec::new();
    loop {
        let tok = lexer.peek()?;
        match tok {
            Token::RBrace | Token::Eof => break,
            _ => stmts.push(parse_stmt(lexer)?),
        }
    }
    Ok(stmts)
}

fn parse_stmt(lexer: &mut Lexer) -> ParseResult<Stmt> {
    let tok = lexer.peek()?;
    match tok {
        Token::Let => parse_let(lexer),
        Token::If => parse_if(lexer),
        Token::While => parse_while(lexer),
        Token::For => parse_for(lexer),
        Token::Return => parse_return(lexer),
        Token::AssertZero => parse_assert_zero(lexer),
        Token::Store => parse_store(lexer),
        Token::Ident(_) => parse_assignment(lexer),
        _ => Err(ParseError {
            message: format!("expected statement, got {tok:?}"),
            position: lexer.pos,
        }),
    }
}

fn parse_let(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::Let)?;
    let name = lexer.expect_ident()?;
    lexer.expect(Token::Eq)?;
    let value = parse_expr(lexer)?;
    lexer.expect(Token::Semicolon)?;
    Ok(Stmt::Let { name, value })
}

fn parse_assignment(lexer: &mut Lexer) -> ParseResult<Stmt> {
    let name = lexer.expect_ident()?;
    lexer.expect(Token::Eq)?;
    let value = parse_expr(lexer)?;
    lexer.expect(Token::Semicolon)?;
    Ok(Stmt::Assign { name, value })
}

fn parse_if(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::If)?;
    let condition = parse_expr(lexer)?;
    lexer.expect(Token::LBrace)?;
    let then_body = parse_block(lexer)?;
    lexer.expect(Token::RBrace)?;
    let else_body = if lexer.peek()? == Token::Else {
        lexer.next_token()?;
        lexer.expect(Token::LBrace)?;
        let body = parse_block(lexer)?;
        lexer.expect(Token::RBrace)?;
        body
    } else {
        vec![]
    };
    Ok(Stmt::If {
        condition,
        then_body,
        else_body,
    })
}

fn parse_while(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::While)?;
    let condition = parse_expr(lexer)?;
    lexer.expect(Token::LBrace)?;
    let body = parse_block(lexer)?;
    lexer.expect(Token::RBrace)?;
    Ok(Stmt::While { condition, body })
}

fn parse_for(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::For)?;
    let var = lexer.expect_ident()?;
    lexer.expect(Token::In)?;
    let start = parse_primary(lexer)?;
    lexer.expect(Token::DotDot)?;
    let end = parse_primary(lexer)?;
    lexer.expect(Token::LBrace)?;
    let body = parse_block(lexer)?;
    lexer.expect(Token::RBrace)?;
    Ok(Stmt::For {
        var,
        start,
        end,
        body,
    })
}

fn parse_return(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::Return)?;
    let expr = parse_expr(lexer)?;
    lexer.expect(Token::Semicolon)?;
    Ok(Stmt::Return(expr))
}

fn parse_assert_zero(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::AssertZero)?;
    lexer.expect(Token::LParen)?;
    let expr = parse_expr(lexer)?;
    lexer.expect(Token::RParen)?;
    lexer.expect(Token::Semicolon)?;
    Ok(Stmt::AssertZero(expr))
}

fn parse_store(lexer: &mut Lexer) -> ParseResult<Stmt> {
    lexer.expect(Token::Store)?;
    lexer.expect(Token::LParen)?;
    let addr = parse_expr(lexer)?;
    lexer.expect(Token::Comma)?;
    let value = parse_expr(lexer)?;
    lexer.expect(Token::RParen)?;
    lexer.expect(Token::Semicolon)?;
    Ok(Stmt::Store { addr, value })
}

// ─── Expression parsing (precedence climbing) ────────────────────────────────

fn parse_expr(lexer: &mut Lexer) -> ParseResult<Expr> {
    parse_comparison(lexer)
}

fn parse_comparison(lexer: &mut Lexer) -> ParseResult<Expr> {
    let mut left = parse_additive(lexer)?;
    loop {
        let tok = lexer.peek()?;
        match tok {
            Token::EqEq => {
                lexer.next_token()?;
                let right = parse_additive(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Eq,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Token::Lt => {
                lexer.next_token()?;
                let right = parse_additive(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Lt,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_additive(lexer: &mut Lexer) -> ParseResult<Expr> {
    let mut left = parse_bitwise(lexer)?;
    loop {
        let tok = lexer.peek()?;
        match tok {
            Token::Plus => {
                lexer.next_token()?;
                let right = parse_bitwise(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Add,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Token::Minus => {
                lexer.next_token()?;
                let right = parse_bitwise(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Sub,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_bitwise(lexer: &mut Lexer) -> ParseResult<Expr> {
    let mut left = parse_shift(lexer)?;
    loop {
        let tok = lexer.peek()?;
        match tok {
            Token::Ampersand => {
                lexer.next_token()?;
                let right = parse_shift(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::And,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Token::Pipe => {
                lexer.next_token()?;
                let right = parse_shift(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Or,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Token::Caret => {
                lexer.next_token()?;
                let right = parse_shift(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Xor,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_shift(lexer: &mut Lexer) -> ParseResult<Expr> {
    let mut left = parse_multiplicative(lexer)?;
    loop {
        let tok = lexer.peek()?;
        match tok {
            Token::Shl => {
                lexer.next_token()?;
                let right = parse_multiplicative(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Shl,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            Token::Shr => {
                lexer.next_token()?;
                let right = parse_multiplicative(lexer)?;
                left = Expr::BinOp {
                    op: BinOp::Shr,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            }
            _ => break,
        }
    }
    Ok(left)
}

fn parse_multiplicative(lexer: &mut Lexer) -> ParseResult<Expr> {
    let mut left = parse_unary(lexer)?;
    loop {
        if lexer.peek()? == Token::Star {
            lexer.next_token()?;
            let right = parse_unary(lexer)?;
            left = Expr::BinOp {
                op: BinOp::Mul,
                left: Box::new(left),
                right: Box::new(right),
            };
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_unary(lexer: &mut Lexer) -> ParseResult<Expr> {
    let tok = lexer.peek()?;
    match tok {
        Token::Minus => {
            lexer.next_token()?;
            let operand = parse_primary(lexer)?;
            Ok(Expr::UnaryOp {
                op: UnaryOp::Neg,
                operand: Box::new(operand),
            })
        }
        Token::Inv => {
            lexer.next_token()?;
            lexer.expect(Token::LParen)?;
            let operand = parse_expr(lexer)?;
            lexer.expect(Token::RParen)?;
            Ok(Expr::UnaryOp {
                op: UnaryOp::Inv,
                operand: Box::new(operand),
            })
        }
        Token::Sq => {
            lexer.next_token()?;
            lexer.expect(Token::LParen)?;
            let operand = parse_expr(lexer)?;
            lexer.expect(Token::RParen)?;
            Ok(Expr::UnaryOp {
                op: UnaryOp::Square,
                operand: Box::new(operand),
            })
        }
        _ => parse_primary(lexer),
    }
}

fn parse_primary(lexer: &mut Lexer) -> ParseResult<Expr> {
    let tok = lexer.next_token()?;
    match tok {
        Token::Number(n) => Ok(Expr::Literal(n)),
        Token::Load => {
            lexer.expect(Token::LParen)?;
            let addr = parse_expr(lexer)?;
            lexer.expect(Token::RParen)?;
            Ok(Expr::Load(Box::new(addr)))
        }
        Token::Ident(name) => {
            // Check for function call: name(args)
            if lexer.peek()? == Token::LParen {
                lexer.next_token()?; // consume '('
                let mut args = Vec::new();
                if lexer.peek()? != Token::RParen {
                    args.push(parse_expr(lexer)?);
                    while lexer.peek()? == Token::Comma {
                        lexer.next_token()?;
                        args.push(parse_expr(lexer)?);
                    }
                }
                lexer.expect(Token::RParen)?;
                Ok(Expr::Call { name, args })
            } else {
                Ok(Expr::Var(name))
            }
        }
        Token::LParen => {
            let expr = parse_expr(lexer)?;
            lexer.expect(Token::RParen)?;
            Ok(expr)
        }
        other => Err(ParseError {
            message: format!("expected expression, got {other:?}"),
            position: lexer.pos,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_function() {
        let source = r#"
            fn main() {
                let x = 5;
                let y = x + 3;
                return y;
            }
        "#;
        let program = parse(source).unwrap();
        assert_eq!(program.functions.len(), 1);
        assert_eq!(program.entry().unwrap().name, "main");
        assert_eq!(program.entry().unwrap().body.len(), 3);
    }

    #[test]
    fn parse_fibonacci() {
        let source = r#"
            fn main() {
                let a = 1;
                let b = 1;
                for i in 0..4 {
                    let tmp = a + b;
                    a = b;
                    b = tmp;
                }
                return a;
            }
        "#;
        let program = parse(source).unwrap();
        let main = program.entry().unwrap();
        assert_eq!(main.body.len(), 4); // let a, let b, for, return
    }

    #[test]
    fn parse_with_params() {
        let source = r#"
            fn add(x, y) {
                return x + y;
            }
        "#;
        let program = parse(source).unwrap();
        let func = program.entry().unwrap();
        assert_eq!(func.params, vec!["x", "y"]);
    }

    #[test]
    fn parse_if_else() {
        let source = r#"
            fn main() {
                let x = 5;
                if x == 5 {
                    let y = 1;
                } else {
                    let y = 0;
                }
                return x;
            }
        "#;
        let program = parse(source).unwrap();
        let main = program.entry().unwrap();
        assert_eq!(main.body.len(), 3); // let, if, return
    }

    #[test]
    fn parse_while_loop() {
        let source = r#"
            fn main() {
                let x = 0;
                while x < 10 {
                    x = x + 1;
                }
                return x;
            }
        "#;
        let program = parse(source).unwrap();
        let main = program.entry().unwrap();
        assert_eq!(main.body.len(), 3);
    }

    #[test]
    fn parse_memory_ops() {
        let source = r#"
            fn main() {
                store(0, 42);
                let x = load(0);
                return x;
            }
        "#;
        let program = parse(source).unwrap();
        let main = program.entry().unwrap();
        assert_eq!(main.body.len(), 3);
    }

    #[test]
    fn parse_assert_zero() {
        let source = r#"
            fn main() {
                let x = 5;
                let y = 5;
                assert_zero(x - y);
            }
        "#;
        let program = parse(source).unwrap();
        let main = program.entry().unwrap();
        assert_eq!(main.body.len(), 3);
    }

    #[test]
    fn parse_complex_expressions() {
        let source = r#"
            fn main() {
                let x = (3 + 4) * 2;
                let y = sq(x) + inv(x);
                return y;
            }
        "#;
        let program = parse(source).unwrap();
        let main = program.entry().unwrap();
        assert_eq!(main.body.len(), 3);
    }

    #[test]
    fn parse_comments() {
        let source = r#"
            // This is a comment
            fn main() {
                let x = 5; // inline comment
                return x;
            }
        "#;
        let program = parse(source).unwrap();
        assert_eq!(program.functions.len(), 1);
    }

    #[test]
    fn parse_error_on_bad_syntax() {
        let source = "fn main( { }";
        assert!(parse(source).is_err());
    }

    #[test]
    fn roundtrip_parse_and_lower() {
        use crate::compiler::lower_to_vm::lower;
        use crate::exec::execute_full;
        use crate::state::VmState;
        use hc_core::field::prime_field::GoldilocksField;
        use hc_core::field::FieldElement;

        type F = GoldilocksField;

        let source = r#"
            fn main() {
                let a = 1;
                let b = 1;
                for i in 0..4 {
                    let tmp = a + b;
                    a = b;
                    b = tmp;
                }
                return a;
            }
        "#;
        let ir = parse(source).unwrap();
        let program = lower(&ir).unwrap();
        let (trace, _) = execute_full::<F>(&program.instructions, VmState::new()).unwrap();
        let last = trace.last().unwrap();
        // fib(6): 1,1,2,3,5,8 → R0 should be 5 (a after 4 iterations from (1,1))
        // Iterations: (1,1)→(1,2)→(2,3)→(3,5)→(5,8)
        // After 4 iterations: a=5
        assert_eq!(last[2], F::from_u64(5)); // R0 = col::R0 = 2
    }
}
