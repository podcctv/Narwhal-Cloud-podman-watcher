use std::collections::{BTreeMap, BTreeSet};

pub const NODE_LIMIT: usize = 12000;
const MAX_PARSE_NODES: usize = 60000;
const MAX_PARSE_DEPTH: usize = 200;
const MAX_TOKENS: usize = 60000;
const MAX_STR_LEN: usize = 4096;
const MAX_INT_ABS: i64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokKind {
    Ident(String),
    Str(String),
    Int(i64),
    Bool(bool),
    NoneLit,
    BytesLit,
    FString,
    OtherLit,
    Kw(&'static str),
    Op(&'static str),
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Dot,
    Semi,
    Eq,
    Newline,
    Indent,
    Dedent,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokKind,
}

fn is_ident_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic() || (!ch.is_ascii() && ch.is_alphabetic())
}

fn is_ident_continue(ch: char) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit() || (!ch.is_ascii() && ch.is_numeric())
}

fn keyword_of(s: &str) -> Option<&'static str> {
    match s {
        "False" => Some("False"),
        "None" => Some("None"),
        "True" => Some("True"),
        "and" => Some("and"),
        "as" => Some("as"),
        "assert" => Some("assert"),
        "async" => Some("async"),
        "await" => Some("await"),
        "break" => Some("break"),
        "class" => Some("class"),
        "continue" => Some("continue"),
        "def" => Some("def"),
        "del" => Some("del"),
        "elif" => Some("elif"),
        "else" => Some("else"),
        "except" => Some("except"),
        "finally" => Some("finally"),
        "for" => Some("for"),
        "from" => Some("from"),
        "global" => Some("global"),
        "if" => Some("if"),
        "import" => Some("import"),
        "in" => Some("in"),
        "is" => Some("is"),
        "lambda" => Some("lambda"),
        "nonlocal" => Some("nonlocal"),
        "not" => Some("not"),
        "or" => Some("or"),
        "pass" => Some("pass"),
        "raise" => Some("raise"),
        "return" => Some("return"),
        "try" => Some("try"),
        "while" => Some("while"),
        "with" => Some("with"),
        "yield" => Some("yield"),
        _ => None,
    }
}

fn push_tok(tokens: &mut Vec<Token>, kind: TokKind) -> Result<(), ()> {
    if tokens.len() >= MAX_TOKENS {
        return Err(());
    }
    tokens.push(Token { kind });
    Ok(())
}

fn scan_string(
    bytes: &[u8],
    src: &str,
    mut pos: usize,
    is_raw: bool,
    is_bytes: bool,
    is_fstr: bool,
) -> Result<(TokKind, usize), ()> {
    let quote = bytes.get(pos).copied().ok_or(())?;
    if quote != b'\'' && quote != b'"' {
        return Err(());
    }
    let triple = bytes.get(pos + 1) == Some(&quote) && bytes.get(pos + 2) == Some(&quote);
    pos += if triple { 3 } else { 1 };

    let mut out = String::new();
    let mut brace_depth = 0usize;

    while pos < bytes.len() {
        if is_fstr && brace_depth == 0 && bytes[pos] == b'{' {
            if bytes.get(pos + 1) == Some(&b'{') {
                pos += 2;
                continue;
            }
            brace_depth += 1;
            pos += 1;
            continue;
        }
        if is_fstr && brace_depth > 0 {
            match bytes[pos] {
                b'{' => {
                    brace_depth += 1;
                    pos += 1;
                }
                b'}' => {
                    brace_depth -= 1;
                    pos += 1;
                }
                b'\'' | b'"' => {
                    let (_, next) = scan_string(bytes, src, pos, is_raw, false, false)?;
                    pos = next;
                }
                b'\\' => {
                    pos += if pos + 1 < bytes.len() { 2 } else { 1 };
                }
                _ => {
                    pos += 1;
                }
            }
            continue;
        }

        if triple {
            if bytes[pos] == quote
                && bytes.get(pos + 1) == Some(&quote)
                && bytes.get(pos + 2) == Some(&quote)
            {
                pos += 3;
                return Ok((
                    if is_fstr {
                        TokKind::FString
                    } else if is_bytes {
                        TokKind::BytesLit
                    } else {
                        TokKind::Str(out)
                    },
                    pos,
                ));
            }
        } else if bytes[pos] == quote {
            pos += 1;
            return Ok((
                if is_fstr {
                    TokKind::FString
                } else if is_bytes {
                    TokKind::BytesLit
                } else {
                    TokKind::Str(out)
                },
                pos,
            ));
        } else if bytes[pos] == b'\n' || bytes[pos] == b'\r' {
            return Err(());
        }

        if bytes[pos] == b'\\' {
            pos += 1;
            if pos >= bytes.len() {
                return Err(());
            }
            if is_raw {
                if !is_bytes && !is_fstr && out.len() <= MAX_STR_LEN + 1 {
                    out.push('\\');
                }
                let ch = src[pos..].chars().next().ok_or(())?;
                if !is_bytes && !is_fstr && out.len() <= MAX_STR_LEN + 1 {
                    out.push(ch);
                }
                pos += ch.len_utf8();
                continue;
            }
            let esc = bytes[pos];
            pos += 1;
            let mapped = match esc {
                b'\n' => None,
                b'\r' => {
                    if bytes.get(pos) == Some(&b'\n') {
                        pos += 1;
                    }
                    None
                }
                b'\\' => Some('\\'),
                b'\'' => Some('\''),
                b'"' => Some('"'),
                b'a' => Some('\x07'),
                b'b' => Some('\x08'),
                b'f' => Some('\x0c'),
                b'n' => Some('\n'),
                b'r' => Some('\r'),
                b't' => Some('\t'),
                b'v' => Some('\x0b'),
                b'x' => {
                    if pos + 2 > bytes.len() {
                        return Err(());
                    }
                    let hex = std::str::from_utf8(&bytes[pos..pos + 2]).map_err(|_| ())?;
                    let v = u32::from_str_radix(hex, 16).map_err(|_| ())?;
                    pos += 2;
                    char::from_u32(v)
                }
                b'u' => {
                    if pos + 4 > bytes.len() {
                        return Err(());
                    }
                    let hex = std::str::from_utf8(&bytes[pos..pos + 4]).map_err(|_| ())?;
                    let v = u32::from_str_radix(hex, 16).map_err(|_| ())?;
                    pos += 4;
                    char::from_u32(v)
                }
                b'U' => {
                    if pos + 8 > bytes.len() {
                        return Err(());
                    }
                    let hex = std::str::from_utf8(&bytes[pos..pos + 8]).map_err(|_| ())?;
                    let v = u32::from_str_radix(hex, 16).map_err(|_| ())?;
                    pos += 8;
                    char::from_u32(v)
                }
                b'0'..=b'7' => {
                    let mut val = (esc - b'0') as u32;
                    for _ in 0..2 {
                        if let Some(&d) = bytes.get(pos) {
                            if matches!(d, b'0'..=b'7') {
                                val = val * 8 + (d - b'0') as u32;
                                pos += 1;
                                continue;
                            }
                        }
                        break;
                    }
                    char::from_u32(val & 0xff)
                }
                other => {
                    if !is_bytes && !is_fstr && out.len() <= MAX_STR_LEN + 1 {
                        out.push('\\');
                    }
                    Some(other as char)
                }
            };
            if let Some(ch) = mapped {
                if !is_bytes && !is_fstr && out.len() <= MAX_STR_LEN + 1 {
                    out.push(ch);
                }
            }
            continue;
        }

        let ch = src[pos..].chars().next().ok_or(())?;
        if !is_bytes && !is_fstr && out.len() <= MAX_STR_LEN + 1 {
            out.push(ch);
        }
        pos += ch.len_utf8();
    }
    Err(())
}

fn scan_number(bytes: &[u8], mut pos: usize) -> Result<(TokKind, usize), ()> {
    let start = pos;
    let mut is_float = false;

    if bytes[pos] == b'0' && pos + 1 < bytes.len() {
        let next = bytes[pos + 1];
        if matches!(next, b'x' | b'X' | b'o' | b'O' | b'b' | b'B') {
            pos += 2;
            let base: u32 = match next {
                b'x' | b'X' => 16,
                b'o' | b'O' => 8,
                _ => 2,
            };
            let mut digits = String::new();
            while pos < bytes.len() {
                let b = bytes[pos];
                if b == b'_' {
                    pos += 1;
                    continue;
                }
                let ok = match base {
                    16 => b.is_ascii_hexdigit(),
                    8 => matches!(b, b'0'..=b'7'),
                    _ => matches!(b, b'0' | b'1'),
                };
                if !ok {
                    break;
                }
                digits.push(b as char);
                pos += 1;
            }
            if digits.is_empty() {
                return Err(());
            }
            let parsed = i64::from_str_radix(&digits, base)
                .ok()
                .filter(|v| v.abs() <= MAX_INT_ABS);
            return Ok((parsed.map(TokKind::Int).unwrap_or(TokKind::OtherLit), pos));
        }
    }

    while pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
        pos += 1;
    }
    if bytes.get(pos) == Some(&b'.') && bytes.get(pos + 1) != Some(&b'.') {
        is_float = true;
        pos += 1;
        while pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
            pos += 1;
        }
    }
    if matches!(bytes.get(pos), Some(b'e' | b'E')) {
        is_float = true;
        pos += 1;
        if matches!(bytes.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        if !matches!(bytes.get(pos), Some(b'0'..=b'9')) {
            return Err(());
        }
        while pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'_') {
            pos += 1;
        }
    }
    if matches!(bytes.get(pos), Some(b'j' | b'J')) {
        pos += 1;
        return Ok((TokKind::OtherLit, pos));
    }

    if is_float {
        return Ok((TokKind::OtherLit, pos));
    }
    let slice = std::str::from_utf8(&bytes[start..pos]).map_err(|_| ())?;
    let clean: String = slice.chars().filter(|&c| c != '_').collect();
    let val = clean.parse::<i64>().ok().filter(|v| v.abs() <= MAX_INT_ABS);
    Ok((val.map(TokKind::Int).unwrap_or(TokKind::OtherLit), pos))
}

fn tokenize(src: &str) -> Result<Vec<Token>, ()> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let mut indent_stack: Vec<usize> = vec![0];
    let mut paren_depth: usize = 0;
    let mut at_line_start = true;
    let mut pos = 0usize;

    // Optional UTF-8 BOM
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        pos = 3;
    }

    while pos < bytes.len() {
        if at_line_start && paren_depth == 0 {
            let mut indent = 0usize;
            while pos < bytes.len() {
                match bytes[pos] {
                    b' ' => {
                        indent += 1;
                        pos += 1;
                    }
                    b'\t' => {
                        indent += 8 - (indent % 8);
                        pos += 1;
                    }
                    _ => break,
                }
            }
            if pos >= bytes.len() {
                break;
            }
            if bytes[pos] == b'#' {
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
                if pos < bytes.len() && bytes[pos] == b'\n' {
                    pos += 1;
                }
                continue;
            }
            if bytes[pos] == b'\r' {
                pos += 1;
                if pos < bytes.len() && bytes[pos] == b'\n' {
                    pos += 1;
                }
                continue;
            }
            if bytes[pos] == b'\n' {
                pos += 1;
                continue;
            }

            let current = *indent_stack.last().unwrap_or(&0);
            if indent > current {
                indent_stack.push(indent);
                push_tok(&mut tokens, TokKind::Indent)?;
            } else if indent < current {
                while let Some(&top) = indent_stack.last() {
                    if indent < top {
                        indent_stack.pop();
                        push_tok(&mut tokens, TokKind::Dedent)?;
                    } else {
                        break;
                    }
                }
                if *indent_stack.last().unwrap_or(&0) != indent {
                    return Err(());
                }
            }
            at_line_start = false;
        }

        if pos >= bytes.len() {
            break;
        }
        let b = bytes[pos];
        match b {
            b' ' | b'\t' | b'\x0c' => {
                pos += 1;
            }
            b'#' => {
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'\\' => {
                pos += 1;
                if bytes.get(pos) == Some(&b'\r') {
                    pos += 1;
                }
                if bytes.get(pos) != Some(&b'\n') {
                    return Err(());
                }
                pos += 1;
            }
            b'\r' => {
                pos += 1;
                if bytes.get(pos) == Some(&b'\n') {
                    pos += 1;
                }
                if paren_depth == 0 {
                    push_tok(&mut tokens, TokKind::Newline)?;
                    at_line_start = true;
                }
            }
            b'\n' => {
                pos += 1;
                if paren_depth == 0 {
                    push_tok(&mut tokens, TokKind::Newline)?;
                    at_line_start = true;
                }
            }
            b'(' => {
                paren_depth += 1;
                pos += 1;
                push_tok(&mut tokens, TokKind::LParen)?;
            }
            b')' => {
                if paren_depth == 0 {
                    return Err(());
                }
                paren_depth -= 1;
                pos += 1;
                push_tok(&mut tokens, TokKind::RParen)?;
            }
            b'[' => {
                paren_depth += 1;
                pos += 1;
                push_tok(&mut tokens, TokKind::LBracket)?;
            }
            b']' => {
                if paren_depth == 0 {
                    return Err(());
                }
                paren_depth -= 1;
                pos += 1;
                push_tok(&mut tokens, TokKind::RBracket)?;
            }
            b'{' => {
                paren_depth += 1;
                pos += 1;
                push_tok(&mut tokens, TokKind::LBrace)?;
            }
            b'}' => {
                if paren_depth == 0 {
                    return Err(());
                }
                paren_depth -= 1;
                pos += 1;
                push_tok(&mut tokens, TokKind::RBrace)?;
            }
            b',' => {
                pos += 1;
                push_tok(&mut tokens, TokKind::Comma)?;
            }
            b';' => {
                pos += 1;
                push_tok(&mut tokens, TokKind::Semi)?;
            }
            b'\'' | b'"' => {
                let (kind, next) = scan_string(bytes, src, pos, false, false, false)?;
                pos = next;
                push_tok(&mut tokens, kind)?;
            }
            b'0'..=b'9' => {
                let (kind, next) = scan_number(bytes, pos)?;
                pos = next;
                push_tok(&mut tokens, kind)?;
            }
            b'.' => {
                if matches!(bytes.get(pos + 1), Some(b'0'..=b'9')) {
                    let (kind, next) = scan_number(bytes, pos)?;
                    pos = next;
                    push_tok(&mut tokens, kind)?;
                } else if bytes.get(pos + 1) == Some(&b'.') && bytes.get(pos + 2) == Some(&b'.') {
                    pos += 3;
                    push_tok(&mut tokens, TokKind::OtherLit)?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Dot)?;
                }
            }
            b':' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op(":="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Colon)?;
                }
            }
            b'=' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("=="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Eq)?;
                }
            }
            b'!' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("!="))?;
                } else {
                    return Err(());
                }
            }
            b'<' => {
                if bytes.get(pos + 1) == Some(&b'<') {
                    if bytes.get(pos + 2) == Some(&b'=') {
                        pos += 3;
                        push_tok(&mut tokens, TokKind::Op("<<="))?;
                    } else {
                        pos += 2;
                        push_tok(&mut tokens, TokKind::Op("<<"))?;
                    }
                } else if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("<="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("<"))?;
                }
            }
            b'>' => {
                if bytes.get(pos + 1) == Some(&b'>') {
                    if bytes.get(pos + 2) == Some(&b'=') {
                        pos += 3;
                        push_tok(&mut tokens, TokKind::Op(">>="))?;
                    } else {
                        pos += 2;
                        push_tok(&mut tokens, TokKind::Op(">>"))?;
                    }
                } else if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op(">="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op(">"))?;
                }
            }
            b'+' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("+="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("+"))?;
                }
            }
            b'-' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("-="))?;
                } else if bytes.get(pos + 1) == Some(&b'>') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("->"))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("-"))?;
                }
            }
            b'*' => {
                if bytes.get(pos + 1) == Some(&b'*') {
                    if bytes.get(pos + 2) == Some(&b'=') {
                        pos += 3;
                        push_tok(&mut tokens, TokKind::Op("**="))?;
                    } else {
                        pos += 2;
                        push_tok(&mut tokens, TokKind::Op("**"))?;
                    }
                } else if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("*="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("*"))?;
                }
            }
            b'/' => {
                if bytes.get(pos + 1) == Some(&b'/') {
                    if bytes.get(pos + 2) == Some(&b'=') {
                        pos += 3;
                        push_tok(&mut tokens, TokKind::Op("//="))?;
                    } else {
                        pos += 2;
                        push_tok(&mut tokens, TokKind::Op("//"))?;
                    }
                } else if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("/="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("/"))?;
                }
            }
            b'%' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("%="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("%"))?;
                }
            }
            b'&' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("&="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("&"))?;
                }
            }
            b'|' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("|="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("|"))?;
                }
            }
            b'^' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("^="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("^"))?;
                }
            }
            b'@' => {
                if bytes.get(pos + 1) == Some(&b'=') {
                    pos += 2;
                    push_tok(&mut tokens, TokKind::Op("@="))?;
                } else {
                    pos += 1;
                    push_tok(&mut tokens, TokKind::Op("@"))?;
                }
            }
            b'~' => {
                pos += 1;
                push_tok(&mut tokens, TokKind::Op("~"))?;
            }
            _ => {
                // Check string prefixes r/u/b/f (1 or 2 chars) followed by quote
                if let Some((prefix_len, is_raw, is_bytes, is_fstr)) =
                    check_string_prefix(bytes, pos)
                {
                    let (kind, next) =
                        scan_string(bytes, src, pos + prefix_len, is_raw, is_bytes, is_fstr)?;
                    pos = next;
                    push_tok(&mut tokens, kind)?;
                    continue;
                }

                let ch = src[pos..].chars().next().ok_or(())?;
                if is_ident_start(ch) {
                    let start = pos;
                    pos += ch.len_utf8();
                    while pos < bytes.len() {
                        let c = src[pos..].chars().next().ok_or(())?;
                        if is_ident_continue(c) {
                            pos += c.len_utf8();
                        } else {
                            break;
                        }
                    }
                    let word = &src[start..pos];
                    let kind = match keyword_of(word) {
                        Some("True") => TokKind::Bool(true),
                        Some("False") => TokKind::Bool(false),
                        Some("None") => TokKind::NoneLit,
                        Some(kw) => TokKind::Kw(kw),
                        None => TokKind::Ident(word.to_string()),
                    };
                    push_tok(&mut tokens, kind)?;
                } else {
                    return Err(());
                }
            }
        }
    }

    if paren_depth != 0 {
        return Err(());
    }
    if !matches!(
        tokens.last().map(|t| &t.kind),
        None | Some(TokKind::Newline | TokKind::Dedent)
    ) {
        push_tok(&mut tokens, TokKind::Newline)?;
    }
    while indent_stack.len() > 1 {
        indent_stack.pop();
        push_tok(&mut tokens, TokKind::Dedent)?;
    }
    push_tok(&mut tokens, TokKind::Eof)?;
    Ok(tokens)
}

fn check_string_prefix(bytes: &[u8], pos: usize) -> Option<(usize, bool, bool, bool)> {
    let b0 = bytes.get(pos)?.to_ascii_lowercase();
    if !matches!(b0, b'r' | b'u' | b'b' | b'f') {
        return None;
    }
    if matches!(bytes.get(pos + 1), Some(b'\'' | b'"')) {
        return Some((1, b0 == b'r', b0 == b'b', b0 == b'f'));
    }
    let b1 = bytes.get(pos + 1)?.to_ascii_lowercase();
    if !matches!(bytes.get(pos + 2), Some(b'\'' | b'"')) {
        return None;
    }
    let pair = [b0, b1];
    let valid = matches!(
        pair,
        [b'r', b'f']
            | [b'f', b'r']
            | [b'r', b'b']
            | [b'b', b'r']
    );
    if valid {
        Some((2, true, b0 == b'b' || b1 == b'b', b0 == b'f' || b1 == b'f'))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// AST Representation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) enum Stmt {
    FuncDef {
        name: String,
        body: Vec<Stmt>,
        active: bool,
    },
    ClassDef,
    If {
        test: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
    },
    While {
        test: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
    },
    For {
        target: Expr,
        iter: Expr,
        body: Vec<Stmt>,
        orelse: Vec<Stmt>,
    },
    With {
        items: Vec<WithItem>,
        body: Vec<Stmt>,
    },
    Try {
        body: Vec<Stmt>,
        handlers: Vec<Vec<Stmt>>,
        orelse: Vec<Stmt>,
        finalbody: Vec<Stmt>,
    },
    Import {
        names: Vec<(String, Option<String>)>,
    },
    ImportFrom {
        module: Option<String>,
        names: Vec<(String, Option<String>)>,
    },
    Assign {
        targets: Vec<Expr>,
        value: Expr,
    },
    Other {
        exprs: Vec<Expr>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct WithItem {
    pub(crate) context_expr: Expr,
    pub(crate) optional_var: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct KeywordArg {
    pub(crate) arg: Option<String>,
    pub(crate) value: Expr,
}

#[derive(Debug, Clone)]
pub(crate) struct DictEntry {
    pub(crate) key: Option<Expr>,
    pub(crate) value: Expr,
}

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Name(String),
    Attr {
        value: Box<Expr>,
        attr: String,
    },
    ConstStr(String),
    ConstInt(i64),
    ConstBool(bool),
    ConstNone,
    ConstOther,
    Add(Box<Expr>, Box<Expr>),
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
        keywords: Vec<KeywordArg>,
    },
    Dict(Vec<DictEntry>),
    Comprehension {
        elts: Vec<Expr>,
        clauses: Vec<(Expr, Vec<Expr>)>,
    },
    Compound(Vec<Expr>),
}

impl Expr {
    pub(crate) fn dotted_name(&self) -> Option<String> {
        match self {
            Expr::Name(id) => Some(id.clone()),
            Expr::Attr { value, attr } => {
                let mut base = value.dotted_name()?;
                base.push('.');
                base.push_str(attr);
                Some(base)
            }
            _ => None,
        }
    }

    pub(crate) fn is_truthy_constant(&self) -> Option<bool> {
        match self {
            Expr::ConstBool(b) => Some(*b),
            Expr::ConstInt(i) => Some(*i != 0),
            Expr::ConstStr(s) => Some(!s.is_empty()),
            Expr::ConstNone => Some(false),
            _ => None,
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    node_count: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            node_count: 0,
        }
    }

    fn bump_node(&mut self) -> Result<(), ()> {
        self.node_count += 1;
        if self.node_count > MAX_PARSE_NODES {
            Err(())
        } else {
            Ok(())
        }
    }

    fn peek(&self) -> &TokKind {
        self.tokens
            .get(self.pos)
            .map(|t| &t.kind)
            .unwrap_or(&TokKind::Eof)
    }

    fn peek_at(&self, offset: usize) -> &TokKind {
        self.tokens
            .get(self.pos + offset)
            .map(|t| &t.kind)
            .unwrap_or(&TokKind::Eof)
    }

    fn next(&mut self) -> TokKind {
        if self.pos < self.tokens.len() {
            let k = self.tokens[self.pos].kind.clone();
            self.pos += 1;
            k
        } else {
            TokKind::Eof
        }
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), TokKind::Kw(k) if *k == kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn eat_op(&mut self, op: &str) -> bool {
        if matches!(self.peek(), TokKind::Op(o) if *o == op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), TokKind::Newline) {
            self.pos += 1;
        }
    }

    fn parse_module(&mut self) -> Result<Vec<Stmt>, ()> {
        let mut stmts = Vec::new();
        loop {
            self.skip_newlines();
            if matches!(self.peek(), TokKind::Eof) {
                break;
            }
            stmts.extend(self.parse_stmt(0)?);
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        if depth > MAX_PARSE_DEPTH {
            return Err(());
        }
        self.bump_node()?;
        if matches!(self.peek(), TokKind::Op("@")) {
            let mut dec_exprs = Vec::new();
            while self.eat_op("@") {
                dec_exprs.push(self.parse_named_expr(depth + 1)?);
                if !matches!(self.peek(), TokKind::Newline) {
                    return Err(());
                }
                self.skip_newlines();
            }
            let mut inner = self.parse_compound_stmt(depth + 1)?;
            if !dec_exprs.is_empty() && !matches!(inner.first(), Some(Stmt::FuncDef { .. } | Stmt::ClassDef)) {
                return Err(());
            }
            if !matches!(inner.first(), Some(Stmt::ClassDef)) {
                // Decorator expressions sit outside the def body at module/enclosing scope.
                let mut out = vec![Stmt::Other { exprs: dec_exprs }];
                out.append(&mut inner);
                return Ok(out);
            }
            return Ok(inner);
        }

        if self.starts_compound_stmt() {
            return self.parse_compound_stmt(depth + 1);
        }
        self.parse_simple_stmts(depth + 1)
    }

    fn starts_compound_stmt(&self) -> bool {
        match self.peek() {
            TokKind::Kw("if" | "while" | "for" | "with" | "try" | "def" | "class") => true,
            TokKind::Kw("async") => {
                matches!(self.peek_at(1), TokKind::Kw("def" | "for" | "with"))
            }
            _ => false,
        }
    }

    fn parse_compound_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        if depth > MAX_PARSE_DEPTH {
            return Err(());
        }
        if self.eat_kw("async") {
            if self.eat_kw("def") {
                return self.parse_func_def(depth);
            }
            if self.eat_kw("for") {
                return self.parse_for_stmt(depth);
            }
            if self.eat_kw("with") {
                return self.parse_with_stmt(depth);
            }
            return Err(());
        }
        if self.eat_kw("def") {
            return self.parse_func_def(depth);
        }
        if self.eat_kw("class") {
            return self.parse_class_def(depth);
        }
        if self.eat_kw("if") {
            return self.parse_if_stmt(depth);
        }
        if self.eat_kw("while") {
            return self.parse_while_stmt(depth);
        }
        if self.eat_kw("for") {
            return self.parse_for_stmt(depth);
        }
        if self.eat_kw("with") {
            return self.parse_with_stmt(depth);
        }
        if self.eat_kw("try") {
            return self.parse_try_stmt(depth);
        }
        Err(())
    }

    fn parse_func_def(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        let name = match self.next() {
            TokKind::Ident(s) => s,
            _ => return Err(()),
        };
        if !matches!(self.next(), TokKind::LParen) {
            return Err(());
        }
        let mut defaults = Vec::new();
        self.skip_param_list(&mut defaults, depth + 1)?;
        if self.eat_op("->") {
            let _ = self.parse_expr(depth + 1)?;
        }
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let body = self.parse_suite(depth + 1)?;
        let mut out = Vec::new();
        if !defaults.is_empty() {
            out.push(Stmt::Other { exprs: defaults });
        }
        out.push(Stmt::FuncDef {
            name,
            body,
            active: false,
        });
        Ok(out)
    }

    fn skip_param_list(&mut self, defaults: &mut Vec<Expr>, depth: usize) -> Result<(), ()> {
        if matches!(self.peek(), TokKind::RParen) {
            self.pos += 1;
            return Ok(());
        }
        loop {
            while matches!(self.peek(), TokKind::Op("*" | "**" | "/")) {
                self.pos += 1;
            }
            if matches!(self.peek(), TokKind::RParen) {
                self.pos += 1;
                return Ok(());
            }
            if matches!(self.peek(), TokKind::Comma) {
                self.pos += 1;
                if matches!(self.peek(), TokKind::RParen) {
                    self.pos += 1;
                    return Ok(());
                }
                continue;
            }
            match self.next() {
                TokKind::Ident(_) => {}
                _ => return Err(()),
            }
            if matches!(self.peek(), TokKind::Colon) {
                self.pos += 1;
                let _ = self.parse_expr(depth + 1)?;
            }
            if matches!(self.peek(), TokKind::Eq) {
                self.pos += 1;
                defaults.push(self.parse_expr(depth + 1)?);
            }
            match self.peek() {
                TokKind::Comma => {
                    self.pos += 1;
                    if matches!(self.peek(), TokKind::RParen) {
                        self.pos += 1;
                        return Ok(());
                    }
                }
                TokKind::RParen => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(()),
            }
        }
    }

    fn parse_class_def(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        match self.next() {
            TokKind::Ident(_) => {}
            _ => return Err(()),
        }
        if matches!(self.peek(), TokKind::LParen) {
            self.pos += 1;
            if !matches!(self.peek(), TokKind::RParen) {
                let _ = self.parse_arg_list(depth + 1)?;
            }
            if !matches!(self.next(), TokKind::RParen) {
                return Err(());
            }
        }
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let _ = self.parse_suite(depth + 1)?;
        Ok(vec![Stmt::ClassDef])
    }

    fn parse_if_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        let test = self.parse_named_expr(depth + 1)?;
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let body = self.parse_suite(depth + 1)?;
        let orelse = if self.eat_kw("elif") {
            self.parse_if_stmt(depth + 1)?
        } else if self.eat_kw("else") {
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            self.parse_suite(depth + 1)?
        } else {
            Vec::new()
        };
        Ok(vec![Stmt::If { test, body, orelse }])
    }

    fn parse_while_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        let test = self.parse_named_expr(depth + 1)?;
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let body = self.parse_suite(depth + 1)?;
        let orelse = if self.eat_kw("else") {
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            self.parse_suite(depth + 1)?
        } else {
            Vec::new()
        };
        Ok(vec![Stmt::While { test, body, orelse }])
    }

    fn parse_for_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        let target = self.parse_target_list(depth + 1)?;
        if !self.eat_kw("in") {
            return Err(());
        }
        let iter = self.parse_tuple_or_expr(depth + 1)?;
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let body = self.parse_suite(depth + 1)?;
        let orelse = if self.eat_kw("else") {
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            self.parse_suite(depth + 1)?
        } else {
            Vec::new()
        };
        Ok(vec![Stmt::For {
            target,
            iter,
            body,
            orelse,
        }])
    }

    fn parse_with_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        let mut items = Vec::new();
        let parenthesized = matches!(self.peek(), TokKind::LParen) && self.looks_like_with_paren();
        if parenthesized {
            self.pos += 1;
        }
        loop {
            let context_expr = self.parse_expr(depth + 1)?;
            let optional_var = if self.eat_kw("as") {
                match self.parse_target_atom(depth + 1)? {
                    Expr::Name(name) => Some(name),
                    _ => None,
                }
            } else {
                None
            };
            items.push(WithItem {
                context_expr,
                optional_var,
            });
            if matches!(self.peek(), TokKind::Comma) {
                self.pos += 1;
                if parenthesized && matches!(self.peek(), TokKind::RParen) {
                    break;
                }
            } else {
                break;
            }
        }
        if parenthesized && !matches!(self.next(), TokKind::RParen) {
            return Err(());
        }
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let body = self.parse_suite(depth + 1)?;
        Ok(vec![Stmt::With { items, body }])
    }

    fn looks_like_with_paren(&self) -> bool {
        let mut depth = 0usize;
        let mut i = self.pos;
        while i < self.tokens.len() {
            match self.tokens[i].kind {
                TokKind::LParen => depth += 1,
                TokKind::RParen => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return matches!(
                            self.tokens.get(i + 1).map(|t| &t.kind),
                            Some(TokKind::Colon)
                        );
                    }
                }
                TokKind::Kw("as") if depth == 1 => return true,
                TokKind::Eof => return false,
                _ => {}
            }
            i += 1;
        }
        false
    }

    fn parse_try_stmt(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        if !matches!(self.next(), TokKind::Colon) {
            return Err(());
        }
        let body = self.parse_suite(depth + 1)?;
        let mut handlers = Vec::new();
        let mut orelse = Vec::new();
        let mut finalbody = Vec::new();
        while self.eat_kw("except") {
            let _ = self.eat_op("*");
            if !matches!(self.peek(), TokKind::Colon) {
                let _ = self.parse_expr(depth + 1)?;
                if self.eat_kw("as") {
                    match self.next() {
                        TokKind::Ident(_) => {}
                        _ => return Err(()),
                    }
                }
            }
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            handlers.push(self.parse_suite(depth + 1)?);
        }
        if !handlers.is_empty() && self.eat_kw("else") {
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            orelse = self.parse_suite(depth + 1)?;
        }
        if self.eat_kw("finally") {
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            finalbody = self.parse_suite(depth + 1)?;
        }
        if handlers.is_empty() && finalbody.is_empty() {
            return Err(());
        }
        Ok(vec![Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
        }])
    }

    fn parse_suite(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        if depth > MAX_PARSE_DEPTH {
            return Err(());
        }
        if matches!(self.peek(), TokKind::Newline) {
            self.skip_newlines();
            if !matches!(self.next(), TokKind::Indent) {
                return Err(());
            }
            let mut body = Vec::new();
            loop {
                self.skip_newlines();
                if matches!(self.peek(), TokKind::Dedent) {
                    self.pos += 1;
                    break;
                }
                if matches!(self.peek(), TokKind::Eof) {
                    return Err(());
                }
                body.extend(self.parse_stmt(depth + 1)?);
            }
            Ok(body)
        } else {
            self.parse_simple_stmts(depth + 1)
        }
    }

    fn parse_simple_stmts(&mut self, depth: usize) -> Result<Vec<Stmt>, ()> {
        let mut stmts = Vec::new();
        loop {
            stmts.push(self.parse_single_simple_stmt(depth + 1)?);
            if matches!(self.peek(), TokKind::Semi) {
                self.pos += 1;
                if matches!(self.peek(), TokKind::Newline | TokKind::Eof | TokKind::Dedent) {
                    break;
                }
                continue;
            }
            break;
        }
        match self.peek() {
            TokKind::Newline => {
                self.pos += 1;
            }
            TokKind::Eof | TokKind::Dedent => {}
            _ => return Err(()),
        }
        Ok(stmts)
    }

    fn parse_single_simple_stmt(&mut self, depth: usize) -> Result<Stmt, ()> {
        self.bump_node()?;
        if self.eat_kw("import") {
            let mut names = Vec::new();
            loop {
                let name = self.parse_dotted_ident()?;
                let asname = if self.eat_kw("as") {
                    match self.next() {
                        TokKind::Ident(s) => Some(s),
                        _ => return Err(()),
                    }
                } else {
                    None
                };
                names.push((name, asname));
                if matches!(self.peek(), TokKind::Comma) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            return Ok(Stmt::Import { names });
        }
        if self.eat_kw("from") {
            let mut dots = 0usize;
            while matches!(self.peek(), TokKind::Dot) {
                self.pos += 1;
                dots += 1;
            }
            let module = if matches!(self.peek(), TokKind::Ident(_)) {
                Some(self.parse_dotted_ident()?)
            } else if dots > 0 {
                None
            } else {
                return Err(());
            };
            if !self.eat_kw("import") {
                return Err(());
            }
            let mut names = Vec::new();
            if self.eat_op("*") {
                names.push(("*".to_string(), None));
            } else {
                let paren = matches!(self.peek(), TokKind::LParen);
                if paren {
                    self.pos += 1;
                }
                loop {
                    if paren && matches!(self.peek(), TokKind::RParen) {
                        break;
                    }
                    let name = match self.next() {
                        TokKind::Ident(s) => s,
                        _ => return Err(()),
                    };
                    let asname = if self.eat_kw("as") {
                        match self.next() {
                            TokKind::Ident(s) => Some(s),
                            _ => return Err(()),
                        }
                    } else {
                        None
                    };
                    names.push((name, asname));
                    if matches!(self.peek(), TokKind::Comma) {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                if paren && !matches!(self.next(), TokKind::RParen) {
                    return Err(());
                }
            }
            return Ok(Stmt::ImportFrom { module, names });
        }
        if self.eat_kw("pass") || self.eat_kw("break") || self.eat_kw("continue") {
            return Ok(Stmt::Other { exprs: Vec::new() });
        }
        if self.eat_kw("global") || self.eat_kw("nonlocal") {
            loop {
                match self.next() {
                    TokKind::Ident(_) => {}
                    _ => return Err(()),
                }
                if matches!(self.peek(), TokKind::Comma) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            return Ok(Stmt::Other { exprs: Vec::new() });
        }
        if self.eat_kw("return") {
            let mut exprs = Vec::new();
            if !matches!(
                self.peek(),
                TokKind::Newline | TokKind::Semi | TokKind::Eof | TokKind::Dedent
            ) {
                exprs.push(self.parse_tuple_or_expr(depth + 1)?);
            }
            return Ok(Stmt::Other { exprs });
        }
        if self.eat_kw("raise") {
            let mut exprs = Vec::new();
            if !matches!(
                self.peek(),
                TokKind::Newline | TokKind::Semi | TokKind::Eof | TokKind::Dedent
            ) {
                exprs.push(self.parse_expr(depth + 1)?);
                if self.eat_kw("from") {
                    exprs.push(self.parse_expr(depth + 1)?);
                }
            }
            return Ok(Stmt::Other { exprs });
        }
        if self.eat_kw("assert") || self.eat_kw("del") {
            let e = self.parse_tuple_or_expr(depth + 1)?;
            return Ok(Stmt::Other { exprs: vec![e] });
        }

        // Assignment, AugAssign, AnnAssign, or ExprStmt
        let first = self.parse_tuple_or_expr(depth + 1)?;
        if matches!(self.peek(), TokKind::Eq) {
            let mut targets = vec![first];
            while matches!(self.peek(), TokKind::Eq) {
                self.pos += 1;
                let rhs = self.parse_tuple_or_expr(depth + 1)?;
                if matches!(self.peek(), TokKind::Eq) {
                    targets.push(rhs);
                } else {
                    return Ok(Stmt::Assign {
                        targets,
                        value: rhs,
                    });
                }
            }
            return Err(());
        }
        if matches!(
            self.peek(),
            TokKind::Op(
                "+=" | "-=" | "*=" | "/=" | "//=" | "%=" | "**=" | "&=" | "|=" | "^=" | ">>=" | "<<=" | "@="
            )
        ) {
            self.pos += 1;
            let rhs = self.parse_tuple_or_expr(depth + 1)?;
            return Ok(Stmt::Other {
                exprs: vec![first, rhs],
            });
        }
        if matches!(self.peek(), TokKind::Colon) {
            self.pos += 1;
            let ann = self.parse_expr(depth + 1)?;
            let mut exprs = vec![first, ann];
            if matches!(self.peek(), TokKind::Eq) {
                self.pos += 1;
                exprs.push(self.parse_tuple_or_expr(depth + 1)?);
            }
            return Ok(Stmt::Other { exprs });
        }
        Ok(Stmt::Other { exprs: vec![first] })
    }

    fn parse_dotted_ident(&mut self) -> Result<String, ()> {
        let mut out = match self.next() {
            TokKind::Ident(s) => s,
            _ => return Err(()),
        };
        while matches!(self.peek(), TokKind::Dot) {
            self.pos += 1;
            match self.next() {
                TokKind::Ident(s) => {
                    out.push('.');
                    out.push_str(&s);
                }
                _ => return Err(()),
            }
        }
        Ok(out)
    }

    fn parse_target_list(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut items = vec![self.parse_target_atom(depth + 1)?];
        while matches!(self.peek(), TokKind::Comma) {
            self.pos += 1;
            if matches!(self.peek(), TokKind::Kw("in") | TokKind::Colon) {
                break;
            }
            items.push(self.parse_target_atom(depth + 1)?);
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Expr::Compound(items))
        }
    }

    fn parse_target_atom(&mut self, depth: usize) -> Result<Expr, ()> {
        if self.eat_op("*") {
            return self.parse_target_atom(depth + 1);
        }
        if matches!(self.peek(), TokKind::LParen | TokKind::LBracket) {
            let close = if matches!(self.next(), TokKind::LParen) {
                TokKind::RParen
            } else {
                TokKind::RBracket
            };
            let mut items = Vec::new();
            if *self.peek() != close {
                loop {
                    items.push(self.parse_target_atom(depth + 1)?);
                    if matches!(self.peek(), TokKind::Comma) {
                        self.pos += 1;
                        if *self.peek() == close {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            if self.next() != close {
                return Err(());
            }
            return Ok(Expr::Compound(items));
        }
        let mut expr = match self.next() {
            TokKind::Ident(s) => Expr::Name(s),
            _ => return Err(()),
        };
        loop {
            if matches!(self.peek(), TokKind::Dot) {
                self.pos += 1;
                let attr = match self.next() {
                    TokKind::Ident(s) => s,
                    _ => return Err(()),
                };
                expr = Expr::Attr {
                    value: Box::new(expr),
                    attr,
                };
            } else if matches!(self.peek(), TokKind::LBracket) {
                self.pos += 1;
                let idx = self.parse_subscript_list(depth + 1)?;
                if !matches!(self.next(), TokKind::RBracket) {
                    return Err(());
                }
                expr = Expr::Compound(vec![expr, idx]);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_tuple_or_expr(&mut self, depth: usize) -> Result<Expr, ()> {
        let first = self.parse_star_named_expr(depth + 1)?;
        if !matches!(self.peek(), TokKind::Comma) {
            return Ok(first);
        }
        let mut items = vec![first];
        while matches!(self.peek(), TokKind::Comma) {
            self.pos += 1;
            if matches!(
                self.peek(),
                TokKind::Newline
                    | TokKind::Semi
                    | TokKind::Eq
                    | TokKind::Colon
                    | TokKind::Eof
                    | TokKind::Dedent
                    | TokKind::RParen
                    | TokKind::RBracket
                    | TokKind::RBrace
            ) {
                break;
            }
            items.push(self.parse_star_named_expr(depth + 1)?);
        }
        Ok(Expr::Compound(items))
    }

    fn parse_star_named_expr(&mut self, depth: usize) -> Result<Expr, ()> {
        if self.eat_op("*") {
            return self.parse_expr(depth + 1);
        }
        self.parse_named_expr(depth + 1)
    }

    fn parse_named_expr(&mut self, depth: usize) -> Result<Expr, ()> {
        let expr = self.parse_expr(depth + 1)?;
        if self.eat_op(":=") {
            let rhs = self.parse_expr(depth + 1)?;
            return Ok(Expr::Compound(vec![expr, rhs]));
        }
        Ok(expr)
    }

    fn parse_expr(&mut self, depth: usize) -> Result<Expr, ()> {
        if depth > MAX_PARSE_DEPTH {
            return Err(());
        }
        self.bump_node()?;
        if self.eat_kw("lambda") {
            while !matches!(self.peek(), TokKind::Colon | TokKind::Eof) {
                self.pos += 1;
            }
            if !matches!(self.next(), TokKind::Colon) {
                return Err(());
            }
            let body = self.parse_expr(depth + 1)?;
            return Ok(Expr::Compound(vec![body]));
        }
        if self.eat_kw("yield") {
            let _ = self.eat_kw("from");
            if matches!(
                self.peek(),
                TokKind::Newline
                    | TokKind::Semi
                    | TokKind::RParen
                    | TokKind::RBracket
                    | TokKind::RBrace
                    | TokKind::Comma
                    | TokKind::Eof
                    | TokKind::Dedent
            ) {
                return Ok(Expr::ConstNone);
            }
            return self.parse_tuple_or_expr(depth + 1);
        }
        let body = self.parse_or(depth + 1)?;
        if self.eat_kw("if") {
            let cond = self.parse_or(depth + 1)?;
            if !self.eat_kw("else") {
                return Err(());
            }
            let orelse = self.parse_expr(depth + 1)?;
            return Ok(Expr::Compound(vec![cond, body, orelse]));
        }
        Ok(body)
    }

    fn parse_or(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_and(depth + 1)?;
        while self.eat_kw("or") {
            let rhs = self.parse_and(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_not(depth + 1)?;
        while self.eat_kw("and") {
            let rhs = self.parse_not(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_not(&mut self, depth: usize) -> Result<Expr, ()> {
        if self.eat_kw("not") {
            let inner = self.parse_not(depth + 1)?;
            return Ok(Expr::Compound(vec![inner]));
        }
        self.parse_cmp(depth + 1)
    }

    fn parse_cmp(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_bitor(depth + 1)?;
        loop {
            let matched = if matches!(
                self.peek(),
                TokKind::Op("==" | "!=" | "<" | "<=" | ">" | ">=")
            ) {
                self.pos += 1;
                true
            } else if self.eat_kw("in") {
                true
            } else if matches!(self.peek(), TokKind::Kw("not"))
                && matches!(self.peek_at(1), TokKind::Kw("in"))
            {
                self.pos += 2;
                true
            } else if self.eat_kw("is") {
                let _ = self.eat_kw("not");
                true
            } else {
                false
            };
            if !matched {
                break;
            }
            let rhs = self.parse_bitor(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_bitor(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_bitxor(depth + 1)?;
        while self.eat_op("|") {
            let rhs = self.parse_bitxor(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_bitxor(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_bitand(depth + 1)?;
        while self.eat_op("^") {
            let rhs = self.parse_bitand(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_bitand(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_shift(depth + 1)?;
        while self.eat_op("&") {
            let rhs = self.parse_shift(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_shift(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_add(depth + 1)?;
        while self.eat_op("<<") || self.eat_op(">>") {
            let rhs = self.parse_add(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_add(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_mul(depth + 1)?;
        loop {
            if self.eat_op("+") {
                let rhs = self.parse_mul(depth + 1)?;
                expr = Expr::Add(Box::new(expr), Box::new(rhs));
            } else if self.eat_op("-") {
                let rhs = self.parse_mul(depth + 1)?;
                expr = Expr::Compound(vec![expr, rhs]);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_mul(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_unary(depth + 1)?;
        while self.eat_op("*")
            || self.eat_op("/")
            || self.eat_op("//")
            || self.eat_op("%")
            || self.eat_op("@")
        {
            let rhs = self.parse_unary(depth + 1)?;
            expr = Expr::Compound(vec![expr, rhs]);
        }
        Ok(expr)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr, ()> {
        if self.eat_op("+") || self.eat_op("-") || self.eat_op("~") || self.eat_kw("await") {
            let inner = self.parse_unary(depth + 1)?;
            return Ok(Expr::Compound(vec![inner]));
        }
        self.parse_power(depth + 1)
    }

    fn parse_power(&mut self, depth: usize) -> Result<Expr, ()> {
        let base = self.parse_postfix(depth + 1)?;
        if self.eat_op("**") {
            let exp = self.parse_unary(depth + 1)?;
            return Ok(Expr::Compound(vec![base, exp]));
        }
        Ok(base)
    }

    fn parse_postfix(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut expr = self.parse_atom(depth + 1)?;
        loop {
            if matches!(self.peek(), TokKind::Dot) {
                self.pos += 1;
                let attr = match self.next() {
                    TokKind::Ident(s) => s,
                    _ => return Err(()),
                };
                expr = Expr::Attr {
                    value: Box::new(expr),
                    attr,
                };
            } else if matches!(self.peek(), TokKind::LParen) {
                self.pos += 1;
                let (args, keywords) = self.parse_arg_list(depth + 1)?;
                if !matches!(self.next(), TokKind::RParen) {
                    return Err(());
                }
                expr = Expr::Call {
                    func: Box::new(expr),
                    args,
                    keywords,
                };
            } else if matches!(self.peek(), TokKind::LBracket) {
                self.pos += 1;
                let idx = self.parse_subscript_list(depth + 1)?;
                if !matches!(self.next(), TokKind::RBracket) {
                    return Err(());
                }
                expr = Expr::Compound(vec![expr, idx]);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn parse_subscript_list(&mut self, depth: usize) -> Result<Expr, ()> {
        let mut parts = Vec::new();
        loop {
            if matches!(self.peek(), TokKind::Colon) {
                self.pos += 1;
                if !matches!(
                    self.peek(),
                    TokKind::Colon | TokKind::Comma | TokKind::RBracket
                ) {
                    parts.push(self.parse_expr(depth + 1)?);
                }
                if matches!(self.peek(), TokKind::Colon) {
                    self.pos += 1;
                    if !matches!(self.peek(), TokKind::Comma | TokKind::RBracket) {
                        parts.push(self.parse_expr(depth + 1)?);
                    }
                }
            } else {
                parts.push(self.parse_expr(depth + 1)?);
                while matches!(self.peek(), TokKind::Colon) {
                    self.pos += 1;
                    if !matches!(
                        self.peek(),
                        TokKind::Colon | TokKind::Comma | TokKind::RBracket
                    ) {
                        parts.push(self.parse_expr(depth + 1)?);
                    }
                }
            }
            if matches!(self.peek(), TokKind::Comma) {
                self.pos += 1;
                if matches!(self.peek(), TokKind::RBracket) {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(Expr::Compound(parts))
    }

    fn parse_arg_list(&mut self, depth: usize) -> Result<(Vec<Expr>, Vec<KeywordArg>), ()> {
        let mut args = Vec::new();
        let mut keywords = Vec::new();
        if matches!(self.peek(), TokKind::RParen) {
            return Ok((args, keywords));
        }
        loop {
            if self.eat_op("**") {
                let val = self.parse_expr(depth + 1)?;
                keywords.push(KeywordArg {
                    arg: None,
                    value: val,
                });
            } else if self.eat_op("*") {
                args.push(self.parse_expr(depth + 1)?);
            } else if matches!(self.peek(), TokKind::Ident(_))
                && matches!(self.peek_at(1), TokKind::Eq)
            {
                let kw_name = match self.next() {
                    TokKind::Ident(s) => s,
                    _ => return Err(()),
                };
                self.pos += 1; // '='
                let val = self.parse_expr(depth + 1)?;
                keywords.push(KeywordArg {
                    arg: Some(kw_name),
                    value: val,
                });
            } else {
                let val = self.parse_named_expr(depth + 1)?;
                if self.eat_kw("for") || (self.eat_kw("async") && self.eat_kw("for")) {
                    let comp = self.parse_comprehension_rest(vec![val], depth + 1)?;
                    args.push(comp);
                } else {
                    args.push(val);
                }
            }

            if matches!(self.peek(), TokKind::Comma) {
                self.pos += 1;
                if matches!(self.peek(), TokKind::RParen) {
                    break;
                }
            } else {
                break;
            }
        }
        Ok((args, keywords))
    }

    fn parse_comprehension_rest(
        &mut self,
        elts: Vec<Expr>,
        depth: usize,
    ) -> Result<Expr, ()> {
        let mut clauses = Vec::new();
        loop {
            let _target = self.parse_target_list(depth + 1)?;
            if !self.eat_kw("in") {
                return Err(());
            }
            let iter = self.parse_or(depth + 1)?;
            let mut ifs = Vec::new();
            while self.eat_kw("if") {
                ifs.push(self.parse_or(depth + 1)?);
            }
            clauses.push((iter, ifs));
            if self.eat_kw("for") {
                continue;
            }
            if matches!(self.peek(), TokKind::Kw("async"))
                && matches!(self.peek_at(1), TokKind::Kw("for"))
            {
                self.pos += 2;
                continue;
            }
            break;
        }
        Ok(Expr::Comprehension { elts, clauses })
    }

    fn parse_atom(&mut self, depth: usize) -> Result<Expr, ()> {
        self.bump_node()?;
        match self.next() {
            TokKind::Ident(s) => Ok(Expr::Name(s)),
            TokKind::Int(v) => Ok(Expr::ConstInt(v)),
            TokKind::Bool(b) => Ok(Expr::ConstBool(b)),
            TokKind::NoneLit => Ok(Expr::ConstNone),
            TokKind::BytesLit | TokKind::OtherLit | TokKind::FString => {
                while matches!(
                    self.peek(),
                    TokKind::Str(_) | TokKind::BytesLit | TokKind::FString
                ) {
                    self.pos += 1;
                }
                Ok(Expr::ConstOther)
            }
            TokKind::Str(mut first) => {
                let mut only_str = true;
                loop {
                    match self.peek() {
                        TokKind::Str(_) => {
                            if let TokKind::Str(s) = self.next() {
                                if first.len() <= MAX_STR_LEN + 1 {
                                    first.push_str(&s);
                                }
                            }
                        }
                        TokKind::FString | TokKind::BytesLit => {
                            self.pos += 1;
                            only_str = false;
                        }
                        _ => break,
                    }
                }
                if only_str {
                    Ok(Expr::ConstStr(first))
                } else {
                    Ok(Expr::ConstOther)
                }
            }
            TokKind::LParen => {
                if matches!(self.peek(), TokKind::RParen) {
                    self.pos += 1;
                    return Ok(Expr::Compound(Vec::new()));
                }
                let first = self.parse_star_named_expr(depth + 1)?;
                if self.eat_kw("for")
                    || (matches!(self.peek(), TokKind::Kw("async"))
                        && matches!(self.peek_at(1), TokKind::Kw("for"))
                        && {
                            self.pos += 2;
                            true
                        })
                {
                    let comp = self.parse_comprehension_rest(vec![first], depth + 1)?;
                    if !matches!(self.next(), TokKind::RParen) {
                        return Err(());
                    }
                    return Ok(comp);
                }
                let mut items = vec![first];
                while matches!(self.peek(), TokKind::Comma) {
                    self.pos += 1;
                    if matches!(self.peek(), TokKind::RParen) {
                        break;
                    }
                    items.push(self.parse_star_named_expr(depth + 1)?);
                }
                if !matches!(self.next(), TokKind::RParen) {
                    return Err(());
                }
                if items.len() == 1 {
                    Ok(items.pop().unwrap())
                } else {
                    Ok(Expr::Compound(items))
                }
            }
            TokKind::LBracket => {
                if matches!(self.peek(), TokKind::RBracket) {
                    self.pos += 1;
                    return Ok(Expr::Compound(Vec::new()));
                }
                let first = self.parse_star_named_expr(depth + 1)?;
                if self.eat_kw("for")
                    || (matches!(self.peek(), TokKind::Kw("async"))
                        && matches!(self.peek_at(1), TokKind::Kw("for"))
                        && {
                            self.pos += 2;
                            true
                        })
                {
                    let comp = self.parse_comprehension_rest(vec![first], depth + 1)?;
                    if !matches!(self.next(), TokKind::RBracket) {
                        return Err(());
                    }
                    return Ok(comp);
                }
                let mut items = vec![first];
                while matches!(self.peek(), TokKind::Comma) {
                    self.pos += 1;
                    if matches!(self.peek(), TokKind::RBracket) {
                        break;
                    }
                    items.push(self.parse_star_named_expr(depth + 1)?);
                }
                if !matches!(self.next(), TokKind::RBracket) {
                    return Err(());
                }
                Ok(Expr::Compound(items))
            }
            TokKind::LBrace => {
                if matches!(self.peek(), TokKind::RBrace) {
                    self.pos += 1;
                    return Ok(Expr::Dict(Vec::new()));
                }
                if self.eat_op("**") {
                    let val = self.parse_expr(depth + 1)?;
                    let entries = vec![DictEntry {
                        key: None,
                        value: val,
                    }];
                    return self.finish_dict(entries, depth);
                }
                let first = self.parse_star_named_expr(depth + 1)?;
                if matches!(self.peek(), TokKind::Colon) {
                    self.pos += 1;
                    let val = self.parse_expr(depth + 1)?;
                    if self.eat_kw("for")
                        || (matches!(self.peek(), TokKind::Kw("async"))
                            && matches!(self.peek_at(1), TokKind::Kw("for"))
                            && {
                                self.pos += 2;
                                true
                            })
                    {
                        let comp =
                            self.parse_comprehension_rest(vec![first, val], depth + 1)?;
                        if !matches!(self.next(), TokKind::RBrace) {
                            return Err(());
                        }
                        return Ok(comp);
                    }
                    let entries = vec![DictEntry {
                        key: Some(first),
                        value: val,
                    }];
                    return self.finish_dict(entries, depth);
                }
                if self.eat_kw("for")
                    || (matches!(self.peek(), TokKind::Kw("async"))
                        && matches!(self.peek_at(1), TokKind::Kw("for"))
                        && {
                            self.pos += 2;
                            true
                        })
                {
                    let comp = self.parse_comprehension_rest(vec![first], depth + 1)?;
                    if !matches!(self.next(), TokKind::RBrace) {
                        return Err(());
                    }
                    return Ok(comp);
                }
                let mut items = vec![first];
                while matches!(self.peek(), TokKind::Comma) {
                    self.pos += 1;
                    if matches!(self.peek(), TokKind::RBrace) {
                        break;
                    }
                    items.push(self.parse_star_named_expr(depth + 1)?);
                }
                if !matches!(self.next(), TokKind::RBrace) {
                    return Err(());
                }
                Ok(Expr::Compound(items))
            }
            _ => Err(()),
        }
    }

    fn finish_dict(&mut self, mut entries: Vec<DictEntry>, depth: usize) -> Result<Expr, ()> {
        while matches!(self.peek(), TokKind::Comma) {
            self.pos += 1;
            if matches!(self.peek(), TokKind::RBrace) {
                break;
            }
            if self.eat_op("**") {
                let val = self.parse_expr(depth + 1)?;
                entries.push(DictEntry {
                    key: None,
                    value: val,
                });
            } else {
                let k = self.parse_expr(depth + 1)?;
                if !matches!(self.next(), TokKind::Colon) {
                    return Err(());
                }
                let v = self.parse_expr(depth + 1)?;
                entries.push(DictEntry {
                    key: Some(k),
                    value: v,
                });
            }
        }
        if !matches!(self.next(), TokKind::RBrace) {
            return Err(());
        }
        Ok(Expr::Dict(entries))
    }
}

// ---------------------------------------------------------------------------
// Reachable Node Traversal (matching `_nodes` and `_reachable_tree`)
// ---------------------------------------------------------------------------

pub(crate) enum ActiveNode<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
}

enum WorkItem<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
}

pub(crate) fn collect_active_nodes<'a>(stmts: &'a [Stmt]) -> Result<Vec<ActiveNode<'a>>, ()> {
    let mut nodes = Vec::new();
    let mut stack: Vec<WorkItem<'a>> = Vec::new();
    for s in stmts.iter().rev() {
        stack.push(WorkItem::Stmt(s));
    }

    while let Some(item) = stack.pop() {
        if nodes.len() + 1 > NODE_LIMIT {
            return Err(());
        }
        match item {
            WorkItem::Stmt(s) => match s {
                Stmt::FuncDef { active, body, .. } => {
                    if !*active {
                        continue;
                    }
                    nodes.push(ActiveNode::Stmt(s));
                    for sub in body.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                }
                Stmt::ClassDef => {
                    continue;
                }
                Stmt::If { test, body, orelse } => {
                    nodes.push(ActiveNode::Stmt(s));
                    if let Some(truthy) = test.is_truthy_constant() {
                        let branch = if truthy { body } else { orelse };
                        for sub in branch.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                    } else {
                        for sub in orelse.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                        for sub in body.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                        stack.push(WorkItem::Expr(test));
                    }
                }
                Stmt::While { test, body, orelse } => {
                    nodes.push(ActiveNode::Stmt(s));
                    if test.is_truthy_constant() == Some(false) {
                        for sub in orelse.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                    } else {
                        for sub in orelse.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                        for sub in body.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                        stack.push(WorkItem::Expr(test));
                    }
                }
                Stmt::For {
                    target,
                    iter,
                    body,
                    orelse,
                } => {
                    nodes.push(ActiveNode::Stmt(s));
                    for sub in orelse.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                    for sub in body.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                    stack.push(WorkItem::Expr(iter));
                    stack.push(WorkItem::Expr(target));
                }
                Stmt::With { items, body } => {
                    nodes.push(ActiveNode::Stmt(s));
                    for sub in body.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                    for wi in items.iter().rev() {
                        stack.push(WorkItem::Expr(&wi.context_expr));
                    }
                }
                Stmt::Try {
                    body,
                    handlers,
                    orelse,
                    finalbody,
                } => {
                    nodes.push(ActiveNode::Stmt(s));
                    for sub in finalbody.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                    for sub in orelse.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                    for h in handlers.iter().rev() {
                        for sub in h.iter().rev() {
                            stack.push(WorkItem::Stmt(sub));
                        }
                    }
                    for sub in body.iter().rev() {
                        stack.push(WorkItem::Stmt(sub));
                    }
                }
                Stmt::Import { .. } | Stmt::ImportFrom { .. } => {
                    nodes.push(ActiveNode::Stmt(s));
                }
                Stmt::Assign { targets, value } => {
                    nodes.push(ActiveNode::Stmt(s));
                    stack.push(WorkItem::Expr(value));
                    for t in targets.iter().rev() {
                        stack.push(WorkItem::Expr(t));
                    }
                }
                Stmt::Other { exprs } => {
                    nodes.push(ActiveNode::Stmt(s));
                    for e in exprs.iter().rev() {
                        stack.push(WorkItem::Expr(e));
                    }
                }
            },
            WorkItem::Expr(e) => {
                nodes.push(ActiveNode::Expr(e));
                match e {
                    Expr::Name(_)
                    | Expr::ConstStr(_)
                    | Expr::ConstInt(_)
                    | Expr::ConstBool(_)
                    | Expr::ConstNone
                    | Expr::ConstOther => {}
                    Expr::Attr { value, .. } => {
                        stack.push(WorkItem::Expr(value));
                    }
                    Expr::Add(l, r) => {
                        stack.push(WorkItem::Expr(r));
                        stack.push(WorkItem::Expr(l));
                    }
                    Expr::Call {
                        func,
                        args,
                        keywords,
                    } => {
                        for kw in keywords.iter().rev() {
                            stack.push(WorkItem::Expr(&kw.value));
                        }
                        for a in args.iter().rev() {
                            stack.push(WorkItem::Expr(a));
                        }
                        stack.push(WorkItem::Expr(func));
                    }
                    Expr::Dict(entries) => {
                        for entry in entries.iter().rev() {
                            stack.push(WorkItem::Expr(&entry.value));
                            if let Some(ref k) = entry.key {
                                stack.push(WorkItem::Expr(k));
                            }
                        }
                    }
                    Expr::Comprehension { elts, clauses } => {
                        for (iter, ifs) in clauses.iter().rev() {
                            for cond in ifs.iter().rev() {
                                stack.push(WorkItem::Expr(cond));
                            }
                            stack.push(WorkItem::Expr(iter));
                        }
                        for elt in elts.iter().rev() {
                            stack.push(WorkItem::Expr(elt));
                        }
                    }
                    Expr::Compound(exprs) => {
                        for sub in exprs.iter().rev() {
                            stack.push(WorkItem::Expr(sub));
                        }
                    }
                }
            }
        }
    }
    Ok(nodes)
}

pub(crate) fn parse_reachable_module(source: &str) -> Result<Vec<Stmt>, ()> {
    let tokens = tokenize(source)?;
    let mut parser = Parser::new(tokens);
    let top_stmts = parser.parse_module()?;

    let mut functions: BTreeMap<String, Stmt> = BTreeMap::new();
    let mut bodies: Vec<Stmt> = Vec::new();
    for stmt in top_stmts {
        match stmt {
            Stmt::FuncDef { ref name, .. } => {
                functions.insert(name.clone(), stmt);
            }
            Stmt::ClassDef => {}
            other => bodies.push(other),
        }
    }

    let mut included: BTreeSet<String> = BTreeSet::new();
    loop {
        let nodes = collect_active_nodes(&bodies)?;
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        for node in nodes {
            if let ActiveNode::Expr(Expr::Call {
                func,
                args,
                keywords,
            }) = node
            {
                if let Some(name) = func.dotted_name() {
                    referenced.insert(name);
                }
                for arg in args {
                    if let Expr::Name(id) = arg {
                        referenced.insert(id.clone());
                    }
                }
                for kw in keywords {
                    if let Expr::Name(id) = &kw.value {
                        referenced.insert(id.clone());
                    }
                }
            }
        }
        let newly: Vec<String> = referenced
            .into_iter()
            .filter(|name| functions.contains_key(name) && !included.contains(name))
            .collect();
        if newly.is_empty() {
            break;
        }
        for name in newly {
            included.insert(name.clone());
            if let Some(mut func_stmt) = functions.get(&name).cloned() {
                if let Stmt::FuncDef { ref mut active, .. } = func_stmt {
                    *active = true;
                }
                bodies.push(func_stmt);
            }
        }
    }
    Ok(bodies)
}
