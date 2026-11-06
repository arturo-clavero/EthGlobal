// The authenticated public XML parser must bind this COMPLETE element-text span.
fn xml_text<let N: u32>(bytes: [u8; N], length: u32) {
    assert((length > 0) & (length <= N), "XML text byte limit");
    for i in 0..N {
        if i < length {
            let c = bytes[i];
            // No markup, entity expansion or XML whitespace normalization inside hidden text.
            assert((c >= 32) & (c <= 126) & (c != 60) & (c != 62) & (c != 38), "Invalid private XML text");
        }
    }
}

fn main(commitment: pub [u8; 32], length: pub u32, preimage: [u8; 528]) {
    let bytes = gcp_private_json::commitment::authenticate::<512>(preimage, length, commitment);
    xml_text(bytes, length);
}

#[test]
fn accepts_iam_arn_and_padding() {
    let arn = "arn:aws:iam::111122223333:user/synthetic".as_bytes();
    xml_text(arn, arn.len());
    xml_text([65, 0], 1);
}

#[test(should_fail_with = "Invalid private XML text")]
fn rejects_hidden_markup() {
    let value = "a</UserId><UserId>b".as_bytes();
    xml_text(value, value.len());
}

#[test(should_fail_with = "Invalid private XML text")]
fn rejects_entity_and_numeric_reference() { xml_text("&#65;".as_bytes(), 5); }

#[test(should_fail_with = "Invalid private XML text")]
fn rejects_cdata_end() { xml_text("]]>".as_bytes(), 3); }

#[test(should_fail_with = "Invalid private XML text")]
fn rejects_line_normalization() { xml_text([65, 13, 10, 66], 4); }

#[test(should_fail_with = "Invalid private XML text")]
fn rejects_non_ascii() { xml_text([65, 255], 2); }

#[test(should_fail_with = "Invalid private XML text")]
fn rejects_zero_byte() { xml_text([65, 0], 2); }

#[test(should_fail_with = "XML text byte limit")]
fn rejects_empty_text() { xml_text([65], 0); }

#[test(should_fail_with = "XML text byte limit")]
fn rejects_length_overrun() { xml_text([65], 2); }
