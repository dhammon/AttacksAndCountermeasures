import pdfplumber
import re
import csv
import sys
from pathlib import Path

def load_words(word_list_path):
    """
    Read the index words from a text file (one per line), strip whitespace, ignore blank lines.
    Returns a list of words.
    """
    words = []
    with open(word_list_path, "r", encoding="utf-8") as f:
        for line in f:
            w = line.strip()
            if w:  # skip empty lines
                words.append(w)
    return words

def compile_patterns(words):
    """
    Given a list of words, return a dict mapping:
      word -> compiled_regex_pattern (with word boundaries, case‐insensitive).
    We use re.escape(word) to handle any special characters.
    """
    patterns = {}
    for w in words:
        # \b ensures whole‐word match. Use IGNORECASE.
        # If you expect phrases (e.g. "packet capture"), \b still works if text has whitespace or punctuation.
        escaped = re.escape(w)
        pattern = re.compile(r"\b" + escaped + r"\b", re.IGNORECASE)
        patterns[w] = pattern
    return patterns

def build_index(pdf_path, patterns):
    """
    Iterate through each page in the PDF and for each pattern, record page numbers.
    Returns a dict: word -> sorted(list_of_page_numbers).
    """
    index_map = { w: [] for w in patterns }
    with pdfplumber.open(pdf_path) as pdf:
        # Page numbers start at 1
        for page_num, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            # If the PDF has columns or weird formatting, consider also page.extract_text(x_tolerance=…) etc.
            for word, patt in patterns.items():
                if patt.search(text):
                    index_map[word].append(page_num)
    return index_map

def write_index_csv(index_map, output_path):
    """
    Write the index_map to a CSV file with columns: word, pages (comma‐separated).
    """
    with open(output_path, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["word", "pages"])
        for word, pages in sorted(index_map.items(), key=lambda x: x[0].lower()):
            # Deduplicate and sort page numbers
            unique_pages = sorted(set(pages))
            pages_str = ",".join(str(p) for p in unique_pages)
            writer.writerow([word, pages_str])

def main():
    if len(sys.argv) != 4:
        print("Usage: python build_index.py /path/to/pdf.pdf /path/to/index_words.txt /path/to/output.csv")
        sys.exit(1)

    pdf_path = Path(sys.argv[1])
    word_list_path = Path(sys.argv[2])
    output_csv = Path(sys.argv[3])

    if not pdf_path.is_file():
        print(f"ERROR: PDF not found: {pdf_path}")
        sys.exit(1)
    if not word_list_path.is_file():
        print(f"ERROR: Word‐list not found: {word_list_path}")
        sys.exit(1)

    print("Loading index words…")
    words = load_words(word_list_path)
    print(f" → {len(words)} words loaded.")

    print("Compiling regex patterns…")
    patterns = compile_patterns(words)

    print("Scanning PDF and building index…")
    index_map = build_index(pdf_path, patterns)

    print("Writing output CSV…")
    write_index_csv(index_map, output_csv)

    print("Done! Index written to:", output_csv)

if __name__ == "__main__":
    main()

