use crate::domain::error::DomainError;

const MAX_SVG_DEPTH: usize = 128;

const FORBIDDEN_ELEMENTS: &[&str] = &[
    "script",
    "foreignobject",
    "iframe",
    "frame",
    "frameset",
    "object",
    "embed",
    "applet",
    "audio",
    "video",
    "source",
    "track",
    "canvas",
    "link",
    "meta",
    "base",
    "form",
    "input",
    "button",
    "textarea",
    "select",
    "include",
    "handler",
    "listener",
    "a",
];

const SMIL_ELEMENTS: &[&str] = &[
    "animate",
    "animatemotion",
    "animatetransform",
    "animatecolor",
    "set",
    "mpath",
];

const URI_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "poster",
    "data",
    "from",
    "to",
    "values",
];

pub fn validate_safe_svg(bytes: &[u8]) -> Result<(), DomainError> {
    let raw = std::str::from_utf8(bytes)
        .map_err(|_| DomainError::InvalidDesktopEntry("SVG icon is not valid UTF-8".to_string()))?;

    if raw
        .chars()
        .any(|c| c == '\0' || (c.is_control() && !matches!(c, '\t' | '\n' | '\r')))
    {
        return Err(DomainError::InvalidDesktopEntry(
            "SVG icon contains forbidden control characters".to_string(),
        ));
    }

    let trimmed = raw.trim_start_matches('\u{FEFF}');
    let mut cursor = trimmed;

    cursor = skip_ws_and_comments(cursor)?;
    if cursor.starts_with("<?xml") {
        let is_xml_decl = cursor
            .as_bytes()
            .get(5)
            .is_some_and(|b| b.is_ascii_whitespace());
        if is_xml_decl {
            let Some(end_idx) = cursor.find("?>") else {
                return Err(DomainError::InvalidDesktopEntry(
                    "unterminated XML declaration in SVG".to_string(),
                ));
            };
            cursor = &cursor[end_idx + 2..];
        }
    }

    cursor = skip_ws_and_comments(cursor)?;
    if cursor.starts_with("<!") || cursor.starts_with("<?") {
        return Err(DomainError::InvalidDesktopEntry(
            "forbidden DTD, ENTITY, CDATA, or processing instruction in SVG prolog".to_string(),
        ));
    }

    let mut stack: Vec<String> = Vec::new();
    let mut saw_root = false;
    let mut style_buffer = String::new();

    while !cursor.is_empty() {
        let in_style = stack.iter().any(|tag| tag == "style");

        if let Some(rest) = cursor.strip_prefix("<!--") {
            if in_style {
                return Err(DomainError::InvalidDesktopEntry(
                    "XML comments inside <style> are forbidden in SVG".to_string(),
                ));
            }
            let Some(end_idx) = rest.find("-->") else {
                return Err(DomainError::InvalidDesktopEntry(
                    "unterminated comment in SVG".to_string(),
                ));
            };
            cursor = &rest[end_idx + 3..];
            continue;
        }

        if cursor.starts_with("<?") || cursor.starts_with("<!") {
            return Err(DomainError::InvalidDesktopEntry(
                "forbidden declaration, CDATA, or processing instruction inside SVG".to_string(),
            ));
        }

        if let Some(after_lt) = cursor.strip_prefix('<') {
            if !saw_root {
                saw_root = true;
            } else if stack.is_empty() {
                return Err(DomainError::InvalidDesktopEntry(
                    "unexpected trailing element after root SVG element".to_string(),
                ));
            }

            if let Some(close_rest) = after_lt.strip_prefix('/') {
                let Some(gt_idx) = close_rest.find('>') else {
                    return Err(DomainError::InvalidDesktopEntry(
                        "unterminated closing tag in SVG".to_string(),
                    ));
                };
                let close_name = close_rest[..gt_idx].trim();
                let local_close = local_xml_name(close_name);
                let Some(expected) = stack.pop() else {
                    return Err(DomainError::InvalidDesktopEntry(
                        "unmatched closing tag in SVG".to_string(),
                    ));
                };
                if expected != local_close {
                    return Err(DomainError::InvalidDesktopEntry(
                        "mismatched closing tag in SVG".to_string(),
                    ));
                }
                if expected == "style" && !stack.iter().any(|tag| tag == "style") {
                    validate_safe_css_text(&style_buffer)?;
                    style_buffer.clear();
                }
                cursor = &close_rest[gt_idx + 1..];
                continue;
            }

            if in_style {
                return Err(DomainError::InvalidDesktopEntry(
                    "nested elements inside <style> are forbidden in SVG".to_string(),
                ));
            }

            let (tag_raw, remaining) = scan_start_tag(after_lt)?;
            let is_self_closing = tag_raw.ends_with('/');
            let tag_body = if is_self_closing {
                &tag_raw[..tag_raw.len() - 1]
            } else {
                tag_raw
            };

            let (raw_tag_name, attrs_raw) = split_tag_name(tag_body)?;
            let local_tag = local_xml_name(raw_tag_name);

            if stack.is_empty() && !saw_root {
                return Err(DomainError::InvalidDesktopEntry(
                    "missing root SVG element".to_string(),
                ));
            }
            if stack.is_empty() && local_tag != "svg" {
                return Err(DomainError::InvalidDesktopEntry(format!(
                    "SVG root element must be <svg>, found <{local_tag}>"
                )));
            }
            if FORBIDDEN_ELEMENTS.contains(&local_tag.as_str()) {
                return Err(DomainError::InvalidDesktopEntry(format!(
                    "forbidden element <{local_tag}> in SVG icon"
                )));
            }

            let attrs = parse_xml_attributes(attrs_raw)?;
            validate_element_attributes(&local_tag, &attrs)?;

            if !is_self_closing {
                if stack.len() >= MAX_SVG_DEPTH {
                    return Err(DomainError::ResourceLimitExceeded {
                        resource: "SVG XML nesting depth".to_string(),
                        limit: MAX_SVG_DEPTH as u64,
                        context: "SVG validation".to_string(),
                    });
                }
                stack.push(local_tag);
            }

            cursor = remaining;
            continue;
        }

        let next_lt = cursor.find('<').unwrap_or(cursor.len());
        let text_chunk = &cursor[..next_lt];
        if !saw_root {
            if !text_chunk.trim().is_empty() {
                return Err(DomainError::InvalidDesktopEntry(
                    "unexpected non-whitespace text before root SVG element".to_string(),
                ));
            }
        } else {
            let decoded_text = decode_xml_entities_strict(text_chunk)?;
            if in_style {
                style_buffer.push_str(&decoded_text);
            }
        }
        cursor = &cursor[next_lt..];
    }

    if !saw_root || !stack.is_empty() {
        return Err(DomainError::InvalidDesktopEntry(
            "incomplete or unclosed root <svg> element".to_string(),
        ));
    }

    Ok(())
}

fn skip_ws_and_comments(mut input: &str) -> Result<&str, DomainError> {
    loop {
        input = input.trim_start();
        if let Some(rest) = input.strip_prefix("<!--") {
            let Some(end_idx) = rest.find("-->") else {
                return Err(DomainError::InvalidDesktopEntry(
                    "unterminated XML comment in SVG prolog".to_string(),
                ));
            };
            input = &rest[end_idx + 3..];
            continue;
        }
        return Ok(input);
    }
}

fn scan_start_tag(after_lt: &str) -> Result<(&str, &str), DomainError> {
    let mut quote: Option<u8> = None;
    let bytes = after_lt.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'<' {
                    return Err(DomainError::InvalidDesktopEntry(
                        "unexpected '<' inside SVG tag".to_string(),
                    ));
                } else if b == b'>' {
                    return Ok((&after_lt[..idx], &after_lt[idx + 1..]));
                }
            }
        }
    }
    Err(DomainError::InvalidDesktopEntry(
        "unterminated SVG start tag".to_string(),
    ))
}

fn split_tag_name(body: &str) -> Result<(&str, &str), DomainError> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(DomainError::InvalidDesktopEntry(
            "empty tag name in SVG".to_string(),
        ));
    }
    let idx = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let name = &trimmed[..idx];
    let rest = &trimmed[idx..];
    if !is_valid_xml_name(name) {
        return Err(DomainError::InvalidDesktopEntry(
            "invalid XML element name in SVG".to_string(),
        ));
    }
    Ok((name, rest))
}

fn parse_xml_attributes(mut raw: &str) -> Result<Vec<(String, String)>, DomainError> {
    let mut attrs = Vec::new();
    loop {
        raw = raw.trim_start();
        if raw.is_empty() {
            break;
        }
        let eq_pos = raw.find('=').ok_or_else(|| {
            DomainError::InvalidDesktopEntry("attribute missing '=' in SVG".to_string())
        })?;
        let name = raw[..eq_pos].trim_end();
        if !is_valid_xml_name(name) {
            return Err(DomainError::InvalidDesktopEntry(
                "invalid XML attribute name in SVG".to_string(),
            ));
        }
        let after_eq = raw[eq_pos + 1..].trim_start();
        let quote_char = after_eq.chars().next().ok_or_else(|| {
            DomainError::InvalidDesktopEntry("missing quoted attribute value in SVG".to_string())
        })?;
        if quote_char != '"' && quote_char != '\'' {
            return Err(DomainError::InvalidDesktopEntry(
                "unquoted attribute value forbidden in SVG".to_string(),
            ));
        }
        let val_start = &after_eq[1..];
        let close_pos = val_start.find(quote_char).ok_or_else(|| {
            DomainError::InvalidDesktopEntry("unterminated attribute value in SVG".to_string())
        })?;
        let raw_val = &val_start[..close_pos];
        let decoded_val = decode_xml_entities_strict(raw_val)?;
        attrs.push((name.to_string(), decoded_val));
        raw = &val_start[close_pos + 1..];
    }
    Ok(attrs)
}

fn validate_element_attributes(
    local_tag: &str,
    attrs: &[(String, String)],
) -> Result<(), DomainError> {
    let is_smil = SMIL_ELEMENTS.contains(&local_tag);
    for (name, val) in attrs {
        let local_attr = local_xml_name(name);
        if name.eq_ignore_ascii_case("xml:base") || local_attr == "base" {
            return Err(DomainError::InvalidDesktopEntry(
                "forbidden xml:base attribute in SVG".to_string(),
            ));
        }
        if local_attr.starts_with("on") {
            return Err(DomainError::InvalidDesktopEntry(format!(
                "forbidden event handler attribute '{local_attr}' in SVG"
            )));
        }

        if is_smil && local_attr == "attributename" {
            let target_attr = local_xml_name(val.trim());
            if target_attr.starts_with("on")
                || URI_ATTRIBUTES.contains(&target_attr.as_str())
                || target_attr == "style"
            {
                return Err(DomainError::InvalidDesktopEntry(
                    "forbidden SMIL attribute target in SVG".to_string(),
                ));
            }
        }

        if local_attr == "style" {
            validate_safe_css_text(val)?;
        }

        if URI_ATTRIBUTES.contains(&local_attr.as_str()) {
            validate_safe_svg_uri(local_tag, &local_attr, val)?;
        } else {
            validate_inline_css_urls_and_schemes(val)?;
        }
    }
    Ok(())
}

fn validate_safe_svg_uri(local_tag: &str, attr: &str, value: &str) -> Result<(), DomainError> {
    if matches!(attr, "from" | "to" | "values") {
        return validate_inline_css_urls_and_schemes(value);
    }

    let compact = strip_ascii_whitespace_and_controls(value);
    let lower = compact.to_ascii_lowercase();
    if lower.starts_with('#') {
        return Ok(());
    }
    if local_tag == "image"
        && (lower.starts_with("data:image/png;base64,")
            || lower.starts_with("data:image/jpeg;base64,")
            || lower.starts_with("data:image/webp;base64,"))
    {
        return Ok(());
    }

    Err(DomainError::InvalidDesktopEntry(format!(
        "forbidden external or active URI in SVG attribute '{attr}'"
    )))
}

fn validate_safe_css_text(css: &str) -> Result<(), DomainError> {
    let unescaped = decode_css_escapes(css);
    let no_comments = strip_css_comments(&unescaped)?;
    let lower = strip_ascii_whitespace_and_controls(&no_comments).to_ascii_lowercase();
    if contains_forbidden_css_construct(&lower) {
        return Err(DomainError::InvalidDesktopEntry(
            "forbidden CSS directive, function, or active scheme in SVG".to_string(),
        ));
    }
    validate_css_url_calls(&lower)
}

fn validate_inline_css_urls_and_schemes(value: &str) -> Result<(), DomainError> {
    let unescaped = decode_css_escapes(value);
    let no_comments = strip_css_comments(&unescaped)?;
    let lower_compact = strip_ascii_whitespace_and_controls(&no_comments).to_ascii_lowercase();
    if contains_forbidden_css_construct(&lower_compact)
        || lower_compact.contains("data:text/html")
        || lower_compact.contains("data:image/svg+xml")
    {
        return Err(DomainError::InvalidDesktopEntry(
            "forbidden script URI scheme or CSS construct inside SVG attribute".to_string(),
        ));
    }
    validate_css_url_calls(&lower_compact)
}

fn contains_forbidden_css_construct(lower_compact: &str) -> bool {
    lower_compact.contains("@import")
        || lower_compact.contains("@font-face")
        || lower_compact.contains("@namespace")
        || lower_compact.contains("expression(")
        || lower_compact.contains("javascript:")
        || lower_compact.contains("vbscript:")
        || lower_compact.contains("behavior:")
        || lower_compact.contains("-moz-binding")
        || lower_compact.contains("image-set(")
        || lower_compact.contains("image(")
        || lower_compact.contains("cross-fade(")
}

fn strip_css_comments(css: &str) -> Result<String, DomainError> {
    if !css.contains("/*") {
        return Ok(css.to_string());
    }
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("*/") else {
            return Err(DomainError::InvalidDesktopEntry(
                "unterminated CSS comment in SVG".to_string(),
            ));
        };
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn validate_css_url_calls(text: &str) -> Result<(), DomainError> {
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find("url(") {
        let after_paren = &text[search_from + rel + 4..];
        let Some(close_idx) = after_paren.find(')') else {
            return Err(DomainError::InvalidDesktopEntry(
                "unterminated CSS url() inside SVG".to_string(),
            ));
        };
        let raw_inner = after_paren[..close_idx].trim();
        let inner = raw_inner.trim_matches(|c| c == '"' || c == '\'').trim();
        if !inner.starts_with('#') {
            return Err(DomainError::InvalidDesktopEntry(
                "non-local CSS url() reference forbidden in SVG".to_string(),
            ));
        }
        search_from += rel + 4 + close_idx + 1;
    }
    Ok(())
}

fn decode_xml_entities_strict(input: &str) -> Result<String, DomainError> {
    if !input.contains('&') {
        return Ok(input.to_string());
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp_idx) = rest.find('&') {
        out.push_str(&rest[..amp_idx]);
        let after_amp = &rest[amp_idx + 1..];
        let Some(semi_idx) = after_amp.find(';') else {
            return Err(DomainError::InvalidDesktopEntry(
                "unterminated XML entity in SVG".to_string(),
            ));
        };
        let entity = &after_amp[..semi_idx];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let code = u32::from_str_radix(&entity[2..], 16).map_err(|_| {
                    DomainError::InvalidDesktopEntry("invalid hex XML entity in SVG".to_string())
                })?;
                let ch = char::from_u32(code).filter(|&c| c != '\0').ok_or_else(|| {
                    DomainError::InvalidDesktopEntry("invalid codepoint in SVG entity".to_string())
                })?;
                out.push(ch);
            }
            _ if entity.starts_with('#') => {
                let code = entity[1..].parse::<u32>().map_err(|_| {
                    DomainError::InvalidDesktopEntry(
                        "invalid decimal XML entity in SVG".to_string(),
                    )
                })?;
                let ch = char::from_u32(code).filter(|&c| c != '\0').ok_or_else(|| {
                    DomainError::InvalidDesktopEntry("invalid codepoint in SVG entity".to_string())
                })?;
                out.push(ch);
            }
            _ => {
                return Err(DomainError::InvalidDesktopEntry(format!(
                    "custom or unknown XML entity '&{entity};' forbidden in SVG"
                )));
            }
        }
        rest = &after_amp[semi_idx + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn decode_css_escapes(input: &str) -> String {
    if !input.contains('\\') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let mut hex = String::new();
        while hex.len() < 6 && chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
            if let Some(d) = chars.next() {
                hex.push(d);
            }
        }
        if !hex.is_empty() {
            if chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
                chars.next();
            }
            if let Ok(code) = u32::from_str_radix(&hex, 16)
                && let Some(decoded) = char::from_u32(code)
                && decoded != '\0'
            {
                out.push(decoded);
            }
        } else if let Some(next_ch) = chars.next() {
            out.push(next_ch);
        }
    }
    out
}

fn strip_ascii_whitespace_and_controls(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_control())
        .collect()
}

fn local_xml_name(name: &str) -> String {
    match name.rsplit_once(':') {
        Some((_, local)) => local.to_ascii_lowercase(),
        None => name.to_ascii_lowercase(),
    }
}

fn is_valid_xml_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::validate_safe_svg;

    #[test]
    fn accepts_clean_svg_with_xml_prolog_defs_gradients_and_local_use() {
        let valid = br##"<?xml version="1.0" encoding="UTF-8"?>
        <!-- clean icon -->
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
          <defs>
            <linearGradient id="g1"><stop offset="0%" stop-color="#fff"/></linearGradient>
            <path id="shape" d="M0 0 L64 64"/>
          </defs>
          <rect width="64" height="64" fill="url(#g1)"/>
          <use href="#shape"/>
        </svg>"##;
        assert!(validate_safe_svg(valid).is_ok());
    }

    #[test]
    fn rejects_all_xss_xxe_smil_foreignobject_and_ssrf_vectors() {
        let vectors: &[&[u8]] = &[
            b"<svg onload = \"alert(1)\"></svg>",
            b"<svg onbegin=\"alert(1)\"></svg>",
            b"<svg><svg:script>alert(1)</svg:script></svg>",
            b"<svg><a href=\"jav&#x61;script:alert(1)\"><rect/></a></svg>",
            b"<svg><use href=\"data:text/html,<script>alert(1)</script>\"/></svg>",
            b"<svg><foreignObject><html><body onload=alert(1)></body></html></foreignObject></svg>",
            b"<svg><rect><set attributeName=\"href\" to=\"javascript:alert(1)\"/></rect></svg>",
            b"<svg><rect><animate attributeName=\"onload\" values=\"alert(1)\"/></rect></svg>",
            b"<!DOCTYPE svg [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><svg>&xxe;</svg>",
            b"<?xml-stylesheet type=\"text/xsl\" href=\"http://evil.invalid/x.xsl\"?><svg/>",
            b"<svg><xi:include href=\"file:///etc/passwd\"/></svg>",
            b"<svg><use xlink:href=\"https://evil.invalid/track.svg#i\"/></svg>",
            b"<svg><style>@import url('https://evil.invalid/a.css');</style></svg>",
            b"<svg><style>@imp<!---->ort url('https://evil.invalid/a.css');</style></svg>",
            b"<svg><style><!-- @import url('https://evil.invalid/a.css'); --></style></svg>",
            b"<svg><style><style></style>@import url('https://evil.invalid/a.css');</style></svg>",
            b"<svg><style>@im/*x*/port url('https://evil.invalid/a.css');</style></svg>",
            b"<svg><style>.a{background:image-set(url('https://evil.invalid/a.png') 1x);}</style></svg>",
            b"<svg><style>.a{background:image('https://evil.invalid/a.png');}</style></svg>",
            b"<svg><style>.a{background:cross-fade(url('https://evil.invalid/a.png'),#000,50%);}</style></svg>",
            b"<svg><style>@font-face{font-family:x;src:url('https://evil.invalid/f.woff2');}</style></svg>",
            b"<svg><style>@namespace svg 'http://www.w3.org/2000/svg';</style></svg>",
            b"<svg xml:base=\"https://evil.invalid/\"><use href=\"#shape\"/></svg>",
            b"<svg><rect style=\"background:url(http://evil.invalid/a)\"/></svg>",
            b"<svg><rect style=\"background:image('https://evil.invalid/a.png')\"/></svg>",
            b"<svg><rect style=\"background:image-set('https://evil.invalid/a.png' 1x)\"/></svg>",
            b"<svg><rect style=\"background:cross-fade(#000,#fff,50%)\"/></svg>",
            b"<html><body><svg></svg></body></html>",
        ];

        for payload in vectors {
            assert!(
                validate_safe_svg(payload).is_err(),
                "expected rejection for SVG payload: {}",
                String::from_utf8_lossy(payload)
            );
        }
    }
}
