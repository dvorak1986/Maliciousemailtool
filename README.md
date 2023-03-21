# Maliciousemailtool
This is a Python code that analyzes email messages that an API scrutinizes for potentially harmful attachments, suspicious links and unsafe URLs.

The code uses various APIs to assess the attachment, including VirusTotal and hybrid analysis, which returns a result of whether it identifies a malicious attachment, giving details concerning it. It creates PDF documents that contain results of its inspections and email text, displaying classified items in different colors.

At first, the MALICIOUS_FILE_TYPE stores file extensions perceive as threats such as ".msc," ".com," and so on. The ANALYTICAL_TOOLS store API URL endpoints used to examine uploaded files or attachment. The 'sandbox_checker' method tests the attachment to determine whether it has a problem using the VirusTotal and hybrid-analysis API.

The 'validate_attachment' method goes through each part of the email message and further filters to check if it has an attachment contained within it; if it contains attachments with any extension stored in MALICIOUS_FILE_TYPES, it calls the sandbox_checker function, passing in the necessary parameters such as attach_data, attach_name, etc.

The 'create_report' method extracts text from emails and analyzed files/attachments/suspicious links to compile them into a final report in PDF format. It displays the overall outcome after comparing maximum analytical tools assessments.

Finally, it will check the reputation of domain names by running domain names against public blacklists. If domain names match any blaclist domains, the user receives the relevant information as feedback.

To implement tests for this code, we can use Python'sunittestmodule. Here are some test cases that can be implemented:
1.	Test is_blacklisted function:
a. Test if the function returns True for blacklisted IP address and an API key and URL within the specified format.
b. Test if the function returns False for non-blacklisted IP address and an API key and URL within the specified format.
c. Test if the function returns False when an exception occurs.
2.	Test sandbox_checker function:
a. Test if the function correctly identifies a malicious attachment with positive detections from analytical tools.
b. Test if the function correctly identifies a safe attachment without any positive detections.
3.	Test validate_attachments function:
a. Test if the function identifies all malicious attachments in an email message.
b. Test if the function correctly identifies all safe attachments in an email message.
4.	Test check_url_reputation function:
a. Test if the function correctly identifies a malicious URL with a bad reputation from all designated DNSBLs.
b. Test if the function correctly identifies a safe URL with a good reputation from all designated DNSBLs.
5.	Test create_report function:
a. Test if the function correctly generates a PDF report with results for all tested components.
b. Test if the function correctly highlights unsafe attachments and suspicious links when they exist in the test data.

Note: These test cases are not comprehensive, and additional tests may be necessary based on your specific requirements.
Here is a sample skeleton of how to structure test cases using Python'sunittestmodule:

import unittest
from unittest.mock import patch

class TestEmailSafetyFunctions(unittest.TestCase):

    def test_is_blacklisted(self):
        # Test case 1a
        self.assertTrue(is_blacklisted("127.0.0.2", "api_key", "https://example.com/api"))

        # Test case 1b
        self.assertFalse(is_blacklisted("127.0.0.1", "api_key", "https://example.com/api"))
 
        # Test case 1c
        with patch.object(requests, 'request', side_effect=Exception()):
            self.assertFalse(is_blacklisted("127.0.0.1", "api_key", "https://example.com/api"))

    def test_sandbox_checker(self):
        # Test case 2a
        self.assertFalse(sandbox_checker("https://www.virustotal.com/vtapi/v2/file/scan", b"malware_data", "malware.txt", "dummy_submission_hash", "api_key"))

        # Test case 2b
        self.assertTrue(sandbox_checker("https://www.virustotal.com/vtapi/v2/file/scan", b"safe_data", "safe.txt", "dummy_submission_hash", "api_key"))

    def test_validate_attachments(self):
        # Test case 3a
        pass
      
        # Test case 3b
        pass

    def test_check_url_reputation(self):
        # Test case 4a
        self.assertFalse(check_url_reputation("http://www.example.com/bad_page"))

        # Test case 4b
        self.assertTrue(check_url_reputation("http://www.example.com/good_page"))

    def test_create_report(self):
        # Test case 5a
        pass

        # Test case 5b
        pass

In this example, we have created a class TestEmailSafetyFunctions that inherits from unittest.TestCase. We then define individual test cases for each function we want to test. Within each test case, we create input data and call the relevant function. We then assert the output of the function against what we expect the result to be.
Finally, we can run all test cases by executing the following command:

if __name__ == '__main__':
    unittest.main()


To run tests for this code, you can follow these steps:
1.	Set up a development environment - This will involve installing the necessary programming and testing tools like Python, Pytest, and Virtual Environments.
2.	Clone the codebase- create a folder in your local machine and clone the repository with the testing code.
3.	Navigate to the directory where the code is stored and run pip install -r requirements.txt to install all dependency packages to the virtual environment.
4.	Open a new file and name it as 'test_email_safety.py' or any other name that works for you.
5.	Import the code file inside the testing file using the commands:
import os 
 import re
 import requests
 from fpdf import FPDF

 from email_safety_report import sandbox_checker, validate_attachments, check_url_reputation, create_report

1.	Define some tests in the testing file. Here, you can test individual components by building functions for each component like sandbox_checker() or all the components by testing the create_report() function.
2.	Once you have written your tests, you can run them by opening up terminal prompt and navigating to project directory and run the command:
```
  pytest test_email_safety.py
  ```
This would run all the tests defined in the testing module / file you created.

Check out the results of the test, if all pass, Congratulations! Otherwise, make sure to review your code with extra attention to fixing what might not be right in accordance with the expected output.

Remember that this is a basic guide, and you may need to consider further steps depending on your specific use case.


To execute the malicious email script, please follow the steps below:
1.	Install the necessary libraries:
•	pip install os
•	pip install re
•	pip install requests
•	pip install fpdf
2.	Copy the script into your project directory.
3.	Run the script in the terminal or command line by typing 
python <script_name>.py



