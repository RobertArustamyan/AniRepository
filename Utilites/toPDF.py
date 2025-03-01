from fpdf import FPDF
import os
# Function that converts Log files to PDF
def to_pdf(input_file_path,output_file):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    with open(input_file_path, "r", encoding="utf-8") as file:
        for line in file:
            pdf.multi_cell(190, 10, txt=line.strip())

    if os.path.exists(output_file):
        os.remove(output_file)
    pdf.output(output_file)


if __name__ == '__main__':
    to_pdf(r"C:\Users\User\PycharmProjects\AniProject\Logs\xss_scan.log", 'test.pdf')
