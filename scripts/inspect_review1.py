import docx

doc = docx.Document(r'C:\Users\adity\Downloads\SWE3004_Review_1_Kubernetes_Threat_Detection_v6.docx')
print("Paragraphs 10-25:")
for i in range(10, 26):
    p = doc.paragraphs[i]
    print(f"P{i:2d} (style={p.style.name}, align={p.alignment}): '{p.text}'")

print("\nWhere do tables appear?")
for i, el in enumerate(doc._body._element):
    tag = el.tag.split('}')[-1]
    if tag == 'tbl':
        print(f"Index {i}: Table")
    elif tag == 'p':
        text = el.text.strip() if el.text else ""
        if len(text) > 0:
            print(f"Index {i}: P '{text[:40]}'")
