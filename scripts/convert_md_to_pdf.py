import os
import textwrap
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors

def _wrap_text(text, width=95):
    if not text:
        return [""]
    return textwrap.wrap(text, width=width)

def convert_md_to_pdf(md_path, pdf_path):
    if not os.path.exists(md_path):
        print(f"Error: {md_path} not found")
        return

    with open(md_path, "r") as f:
        lines = f.readlines()

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 50
    margin = 50
    line_height = 14

    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin, y, "CloudGuard Documentation")
    y -= 30

    in_code_block = False
    code_lines = []

    for line in lines:
        line = line.strip('\n')
        
        if line.startswith("```"):
            if in_code_block:
                # End of code block
                c.setFont("Courier", 9)
                c.setFillColor(colors.lightgrey)
                # Background for code block could be added here
                for code_line in code_lines:
                    if y < 50:
                        c.showPage()
                        y = height - 50
                    c.setFillColor(colors.black)
                    c.drawString(margin + 10, y, code_line)
                    y -= 10
                y -= 10
                code_lines = []
                in_code_block = False
            else:
                in_code_block = True
            continue

        if in_code_block:
            code_lines.append(line)
            continue

        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 10)

        if line.startswith("# "):
            c.setFont("Helvetica-Bold", 16)
            c.drawString(margin, y, line[2:])
            y -= 24
        elif line.startswith("## "):
            c.setFont("Helvetica-Bold", 14)
            c.drawString(margin, y, line[3:])
            y -= 20
        elif line.startswith("### "):
            c.setFont("Helvetica-Bold", 12)
            c.drawString(margin, y, line[4:])
            y -= 18
        elif line.strip() == "":
            y -= 10
        else:
            c.setFont("Helvetica", 10)
            wrapped = _wrap_text(line, width=100)
            for w in wrapped:
                if y < 50:
                    c.showPage()
                    y = height - 50
                    c.setFont("Helvetica", 10)
                c.drawString(margin, y, w)
                y -= line_height

    c.save()
    print(f"✅ Successfully converted {md_path} to {pdf_path}")

if __name__ == "__main__":
    base_dir = "/Users/samyukthajagannath/.gemini/antigravity/brain/24e0e5a9-ced3-4d2a-8573-0ed8e6413f3d"
    
    # Files to convert
    files = [
        "credential_management",
        "overall_implementation_explanation"
    ]
    
    for f_name in files:
        md_file = os.path.join(base_dir, f"{f_name}.md")
        pdf_file = os.path.join(base_dir, f"{f_name}.pdf")
        convert_md_to_pdf(md_file, pdf_file)
