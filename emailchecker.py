import os
import re
import requests
from fpdf import FPDF

MALICIOUS_FILE_TYPES = {"exe", "pif", "application", "gadget", "msi", "msp", "com", "scr", "hta", "cpl", "msc"}
ANALYTICAL_TOOLS = [
  "https://www.virustotal.com/vtapi/v2/file/scan",
  "https://any.run/api/search?query={0}",
  "https://www.hybrid-analysis.com/api/v2/search/hash"
]

def is_blacklisted(ip_address, api_key, api_url):
    querystring = {'ipAddress': ip_address}
    headers = {'Accept': 'application/json', 'Key': api_key}

    try:
        response = requests.request('GET', api_url, headers=headers, params=querystring).json()
        if 'data' in response:
            return not response['data']['isWhitelisted'] and response['data']['abuseConfidenceScore'] >= 90
        else:
            return False     
    except Exception as e:
        print(f"Error: {e}")
        return False


def sandbox_checker(url, attachment_data, attach_name, submission_hash, api_key):
    scan_file_param = {"apikey": api_key}
    try:
        response = requests.post(url, files={"file": attachment_data}, data=scan_file_param)
        json_response = response.json()
        permalink = json_response["permalink"]
    except:
        print(f"Failed to get response from {url}")
        return 
        
    if len(json_response["positives"]) > 0:
        print(f'Malicious attachment detected: {attach_name}\nAnyrun Search link: https://app.any.run/tasks/{submission_hash}\nVirustotal analysis link:{permalink}\n\n')
        return False
    else:
        print("Safe Attachment")
        return True 


def validate_attachments(email_message, api_key):
    for part in email_message.walk():
        attach_name = part.get_filename()
        if attach_name:
            file_type = attach_name.split(".")[-1].lower()
            if file_type in MALICIOUS_FILE_TYPES and part.get_content_type() == "application/octet-stream":
                attach_data = part.get_payload(decode=True)
                for url in ANALYTICAL_TOOLS:
                    sandbox_checker(url, attach_data, attach_name, "dummy submission hash", api_key)


def check_url_reputation(url):
    domain = url.split("/")[2]
    dnsbl_urls = [
        "zen.spamhaus.org",
        "dnsbl.sorbs.net",
        "bl.spamcop.net",
        "xbl.spamhaus.org"
    ]

    for dnsbl in dnsbl_urls:
        addr = '.'.join(reversed(domain.split("."))) + "." + dnsbl
        response = os.system("host " + addr)
        if response == 0:
            return False

    return True


def create_report(text, results, has_unsafe_attachment=False, has_suspicious_link=False):
    pdf = FPDF()
    pdf.add_page()

    # Add titles to the report
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Email Safety Report', 0, 1)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, 'Text:', 0, 1)
    pdf.cell(0, 5, text, 0, 1)
    pdf.cell(0, 10, '', 0, 1)
    pdf.cell(0, 5, 'Results:', 0, 1)

    # Add each result to the report
    for result in results:
        # Set the color of the result depending on whether the email is safe or not
        if result[1]:
            pdf.set_text_color(0, 128, 0)  # Green color for safe emails
        else:
            pdf.set_text_color(255, 0, 0) 
        pdf.cell(0, 5, f'{result[0]}: {"Safe" if result[1] else "Unsafe"}', 0, 1)

    # Reset the text color to black
    pdf.set_text_color(0)

    # Add a section for unsafe attachments (if applicable)
    if has_unsafe_attachment:
        pdf.set_text_color(255, 0, 0)
        pdf.cell(0, 10, '', 0, 1)
        pdf.cell(0, 5, 'Unsafe Attachments Detected!', 0, 1)
        pdf.set_text_color(0)

    # Add a section for suspicious links (if applicable)
    if has_suspicious_link:
        pdf.set_text_color(255, 165, 0) 
# Orange color for suspicious links
    pdf.cell(0, 10, '', 0, 1)
    pdf.cell(0, 5, 'Suspicious Links Detected!', 0, 1)
    pdf.set_text_color(0)

# Save the PDF report to a file
pdf.output('report.pdf')

