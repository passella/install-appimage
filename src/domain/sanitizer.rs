use std::fmt::Write as _;

pub fn is_bidi_or_invisible_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

pub fn sanitize_single_line_value(raw: &str) -> String {
    let stripped = strip_ansi_sequences(raw);
    let mut clean = String::with_capacity(stripped.len());
    let mut last_space = false;
    for ch in stripped.chars() {
        if is_bidi_or_invisible_format(ch) {
            continue;
        }
        if ch.is_control() || ch.is_whitespace() {
            if !last_space && !clean.is_empty() {
                clean.push(' ');
                last_space = true;
            }
        } else {
            clean.push(ch);
            last_space = false;
        }
    }
    clean.trim().to_string()
}

pub fn sanitize_terminal_text(raw: &str) -> String {
    sanitize_single_line_value(raw)
}

pub fn sanitize_for_error(raw: &str) -> String {
    const MAX_ERROR_PREVIEW_CHARS: usize = 512;
    let mut out = String::with_capacity(raw.len().min(MAX_ERROR_PREVIEW_CHARS));
    for (count, ch) in raw.chars().enumerate() {
        if count >= MAX_ERROR_PREVIEW_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            let _ = write!(out, "{}", ch.escape_default());
        } else if is_bidi_or_invisible_format(ch) {
            let _ = write!(out, "{}", ch.escape_unicode());
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn escape_desktop_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for (idx, ch) in raw.chars().enumerate() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' ' if idx == 0 => out.push_str("\\s"),
            other => out.push(other),
        }
    }
    out
}

pub fn escape_desktop_list_item(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for (idx, ch) in raw.chars().enumerate() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' ' if idx == 0 => out.push_str("\\s"),
            other => out.push(other),
        }
    }
    out
}

pub fn escape_desktop_exec_path(raw_path: &str) -> Result<String, String> {
    if raw_path.is_empty() {
        return Err("empty executable path".to_string());
    }
    if raw_path
        .chars()
        .any(|ch| ch.is_control() || is_bidi_or_invisible_format(ch))
    {
        return Err("executable path contains forbidden control or BiDi characters".to_string());
    }

    let percent_escaped = raw_path.replace('%', "%%");
    let needs_quoting = percent_escaped.chars().any(|ch| {
        ch.is_whitespace()
            || matches!(
                ch,
                '\x22'
                    | '\x27'
                    | '\\'
                    | '>'
                    | '<'
                    | '~'
                    | '|'
                    | '&'
                    | ';'
                    | '$'
                    | '*'
                    | '?'
                    | '#'
                    | '('
                    | ')'
                    | '`'
                    | '='
            )
    });

    let layer2 = if !needs_quoting {
        percent_escaped
    } else {
        let mut quoted = String::with_capacity(percent_escaped.len() + 8);
        quoted.push('\x22');
        for ch in percent_escaped.chars() {
            match ch {
                '\x22' | '`' | '$' | '\\' => {
                    quoted.push('\\');
                    quoted.push(ch);
                }
                other => quoted.push(other),
            }
        }
        quoted.push('\x22');
        quoted
    };

    Ok(escape_desktop_value(&layer2))
}

pub fn strip_ansi_sequences(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for next_ch in chars.by_ref() {
                        if ('@'..='~').contains(&next_ch) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    consume_until_string_terminator(&mut chars, true);
                }
                Some('P' | 'X' | '^' | '_') => {
                    chars.next();
                    consume_until_string_terminator(&mut chars, false);
                }
                Some(next_ch) if ('\x20'..='\x7e').contains(&next_ch) => {
                    chars.next();
                }
                _ => {}
            }
            continue;
        }

        if ch == '\u{009b}' {
            for next_ch in chars.by_ref() {
                if ('@'..='~').contains(&next_ch) {
                    break;
                }
            }
            continue;
        }

        if ch == '\u{009d}' {
            consume_until_string_terminator(&mut chars, true);
            continue;
        }

        if matches!(ch, '\u{0090}' | '\u{0098}' | '\u{009e}' | '\u{009f}') {
            consume_until_string_terminator(&mut chars, false);
            continue;
        }

        out.push(ch);
    }

    out
}

fn consume_until_string_terminator(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    allow_bel: bool,
) {
    while let Some(next_ch) = chars.next() {
        if next_ch == '\u{009c}' || (allow_bel && next_ch == '\x07') {
            break;
        }
        if next_ch == '\x1b' && chars.peek().copied() == Some('\\') {
            chars.next();
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        escape_desktop_exec_path, escape_desktop_list_item, is_bidi_or_invisible_format,
        sanitize_for_error, sanitize_single_line_value, sanitize_terminal_text,
    };

    #[test]
    fn strips_ansi_csi_osc_dcs_apc_and_unicode_tags() {
        let input = "\x1b[31mEvil\x1b[0m\x1b]2;pwned\x07\x1bPtmux;\x1b\\ \x1b_apc\x1b\\ \u{0090}dcs\u{009c}\u{202E}txt\u{E0020}\r\nnext\u{009b}2J\u{FEFF}";
        let clean = sanitize_terminal_text(input);
        assert_eq!(clean, "Evil txt next");
        assert!(!clean.chars().any(char::is_control));
        assert!(!clean.chars().any(is_bidi_or_invisible_format));
        assert_eq!(sanitize_single_line_value("  a\tb\nc  "), "a b c");
    }

    #[test]
    fn escapes_error_strings_and_truncates() {
        let input = "bad\x1b[31m\r\n\0\u{202E}\u{E0041}name";
        let escaped = sanitize_for_error(input);
        assert_eq!(escaped, "bad\\u{1b}[31m\\r\\n\\u{0}\\u{202e}\\u{e0041}name");

        let long = "a".repeat(600);
        let truncated = sanitize_for_error(&long);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() < 520);
    }

    #[test]
    fn composes_layer1_and_layer2_desktop_exec_escaping_and_list_items() {
        assert_eq!(
            escape_desktop_exec_path("/home/user/Applications/obsidian.AppImage"),
            Ok("/home/user/Applications/obsidian.AppImage".to_string())
        );
        assert_eq!(
            escape_desktop_exec_path("/home/my user/Applications/my$app\"`\\50%.AppImage"),
            Ok(
                "\"/home/my user/Applications/my\\\\$app\\\\\"\\\\`\\\\\\\\50%%.AppImage\""
                    .to_string()
            )
        );
        assert_eq!(escape_desktop_list_item("a\\b;c"), "a\\\\b\\;c");
        assert!(escape_desktop_exec_path("/home/user/app\nrm -rf /").is_err());
        assert!(escape_desktop_exec_path("/home/user/\u{E0041}app").is_err());
        assert!(escape_desktop_exec_path("").is_err());
    }
}
