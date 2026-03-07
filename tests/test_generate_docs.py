from tools.generate_docs import (
    generate_docs_markdown,
    generate_operation_doc,
    get_support_annotation,
    render_method_name,
)


def test_render_method_name_normalizes_unicode_and_punctuation():
    assert render_method_name("Vigenère Decode") == "VigenereDecode"
    assert render_method_name("JSON to CSV") == "JSONToCSV"



def test_get_support_annotation_marks_explicitly_unsupported_operation():
    note = get_support_annotation("Argon2")

    assert note is not None
    assert "unsupported" in note.lower()



def test_generate_operation_doc_includes_support_note():
    operation = {
        "name": "Magic",
        "module": "Default",
        "description": "Browser-backed file magic detection.",
        "infoURL": None,
        "inputType": "ArrayBuffer",
        "outputType": "string",
        "args": [],
        "category": "Flow control",
        "is_favorite": False,
    }

    doc = generate_operation_doc(operation)

    assert "### `Magic()`" in doc
    assert "Support:" in doc
    assert "unsupported" in doc.lower()



def test_generate_docs_markdown_covers_every_schema_operation():
    schema = {
        "operations": [
            {
                "name": "Jsonata Query",
                "module": "Default",
                "description": "Query JSON values.",
                "infoURL": None,
                "inputType": "JSON",
                "outputType": "JSON",
                "args": [],
                "category": "Extractors",
                "is_favorite": False,
            },
            {
                "name": "Vigenère Decode",
                "module": "Ciphers",
                "description": "Decode Vigenère text.",
                "infoURL": None,
                "inputType": "string",
                "outputType": "string",
                "args": [],
                "category": "Encryption / Encoding",
                "is_favorite": False,
            },
        ]
    }

    markdown = generate_docs_markdown(schema)

    assert "This document lists all 2 available CyberChef operations." in markdown
    assert "### `JsonataQuery()`" in markdown
    assert "### `VigenereDecode()`" in markdown
