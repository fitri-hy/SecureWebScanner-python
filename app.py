import streamlit as st
import requests
from bs4 import BeautifulSoup
import logging
import time
from urllib.parse import urljoin
from sklearn.tree import DecisionTreeClassifier
import numpy as np
import re

logging.basicConfig(filename="scan_logs.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

X_train = np.array([
    [0.5, 0, 0],  
    [2.0, 1, 1],  
    [0.3, 0, 0],  
    [1.5, 1, 1],  
    [1.0, 0, 0],  
    [0.7, 1, 0],  
])
y_train = [0, 1, 0, 1, 0, 0]

clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)

def scan_website(url):
    try:
        response = requests.get(url)
        logging.info(f"Scanning URL: {url} - Status Code: {response.status_code}")
        if response.status_code != 200:
            return f"Error: {response.status_code}", None, None
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup, response.headers, response
    except Exception as e:
        logging.error(f"Error scanning {url}: {e}")
        return f"Error: {e}", None, None

def detect_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 'x'='x", "'; DROP TABLE users; --"]
    for payload in payloads:
        test_url = f"{url}?input={payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text or "SQL" in response.text:
                return True
        except requests.RequestException as e:
            logging.error(f"Error testing for SQL Injection: {e}")
    return False

def detect_xss(url):
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    for payload in xss_payloads:
        test_url = f"{url}?input={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                return True
        except requests.RequestException as e:
            logging.error(f"Error testing for XSS: {e}")
    return False

def check_headers(headers):
    header_issues = []
    if "Strict-Transport-Security" not in headers:
        header_issues.append("HSTS (Strict-Transport-Security) header missing.")
    if "X-Frame-Options" not in headers:
        header_issues.append("X-Frame-Options header missing.")
    if "X-XSS-Protection" not in headers:
        header_issues.append("X-XSS-Protection header missing.")
    if "Content-Security-Policy" not in headers:
        header_issues.append("Content-Security-Policy header missing.")
    return header_issues

def give_suggestions(sql_injection, xss, headers):
    suggestions = []
    if sql_injection:
        suggestions.append("Potential SQL Injection detected. Check input validation on the server.")
    if xss:
        suggestions.append("Potential XSS detected. Ensure proper user input sanitization.")
    if "HSTS" not in headers:
        suggestions.append("The site does not use HSTS for protection against downgrade attacks.")
    if "X-Frame-Options" not in headers:
        suggestions.append("Add X-Frame-Options to prevent clickjacking.")
    if "X-XSS-Protection" not in headers:
        suggestions.append("Enable X-XSS-Protection to prevent XSS attacks.")
    if "Content-Security-Policy" not in headers:
        suggestions.append("Add Content-Security-Policy to protect against script injection attacks.")
    return suggestions

def find_all_urls(url, soup):
    urls = set()
    for link in soup.find_all("a", href=True):
        href = link.get("href")
        full_url = urljoin(url, href)
        urls.add(full_url)
    return list(urls)

def predict_security_risk(response_time, headers, page_content):
    missing_headers = 0
    if "Strict-Transport-Security" not in headers:
        missing_headers += 1
    if "X-Frame-Options" not in headers:
        missing_headers += 1
    if "X-XSS-Protection" not in headers:
        missing_headers += 1
    if "Content-Security-Policy" not in headers:
        missing_headers += 1

    error_keywords = ["SQL", "syntax", "error", "warning", "alert"]
    error_in_content = any(keyword in page_content for keyword in error_keywords)

    features = np.array([[response_time, missing_headers, error_in_content]])
    prediction = clf.predict(features)
    return prediction[0]

def check_https(url):
    return url.startswith("https://")

def check_robots_txt(url):
    robots_url = urljoin(url, "robots.txt")
    response = requests.get(robots_url)
    if response.status_code == 200:
        return True
    return False

def check_emails(soup):
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", str(soup)))
    return emails

def seo_analysis(soup):
    title = soup.find("title")
    description = soup.find("meta", attrs={"name": "description"})
    keywords = soup.find("meta", attrs={"name": "keywords"})

    title_valid = bool(title)
    description_valid = bool(description)
    keywords_valid = bool(keywords)

    return title_valid, description_valid, keywords_valid

st.title("🔍 Secure Web Scanner 🚀")
st.subheader("Scan your website for potential vulnerabilities")

url_input = st.text_input("Enter Website URL", "")

if st.button('Start Scan'):
    if url_input:
        st.write(f"🔍 Scanning website: {url_input}...")
        start_time = time.time()
        soup, headers, response = scan_website(url_input)
        
        if isinstance(soup, BeautifulSoup):
            st.success("✅ Page successfully fetched. Analyzing vulnerabilities...")
            
            sql_injection = detect_sql_injection(url_input)
            xss = detect_xss(url_input)
            header_issues = check_headers(headers)
            suggestions = give_suggestions(sql_injection, xss, headers)
            
            response_time = time.time() - start_time
            page_content = response.text
            security_risk = predict_security_risk(response_time, headers, page_content)
            
            with st.expander(f"🔐 Scan Results for **{url_input}**"):
                if sql_injection:
                    st.warning("🚨 **Potential SQL Injection detected!**")
                else:
                    st.info("✔️ The website seems secure from SQL Injection.")
                
                if xss:
                    st.warning("🚨 **Potential XSS vulnerability detected!**")
                else:
                    st.info("✔️ The website seems secure from XSS vulnerabilities.")
                
                if header_issues:
                    st.error("❌ **Issues detected with HTTP headers:**")
                    for issue in header_issues:
                        st.write(f"- {issue}")
                
                if suggestions:
                    st.warning("💡 **Security Recommendations:**")
                    for suggestion in suggestions:
                        st.write(f"- {suggestion}")

                if security_risk == 1:
                    st.error("❗ **IMPORTANT!! detected potential security risks!**")
                else:
                    st.success("✔️ **No major security risks detected according to the model.**")

            st.write(f"⏱️ Website Load Time: {response_time:.2f} seconds.")
            if response_time > 2:
                st.warning("⚠️ Website load time is above the recommended threshold of 2 seconds.")
            else:
                st.success("✅ Website load time is optimal.")
            
            if check_https(url_input):
                st.success("✔️ The website uses HTTPS.")
            else:
                st.warning("⚠️ The website does not use HTTPS. Consider using HTTPS for security.")
            
            if check_robots_txt(url_input):
                st.success("✔️ The website has a robots.txt file.")
            else:
                st.warning("⚠️ The website is missing a robots.txt file.")
            
            emails = check_emails(soup)
            if emails:
                st.warning(f"⚠️ Found email addresses on the page: {', '.join(emails)}")
            else:
                st.info("✔️ No email addresses found on the page.")
            
            title_valid, description_valid, keywords_valid = seo_analysis(soup)
            st.write("🔍 SEO Analysis:")
            if title_valid:
                st.success("✔️ Title tag is present.")
            else:
                st.warning("⚠️ Title tag is missing.")
            if description_valid:
                st.success("✔️ Meta description is present.")
            else:
                st.warning("⚠️ Meta description is missing.")
            if keywords_valid:
                st.success("✔️ Meta keywords are present.")
            else:
                st.warning("⚠️ Meta keywords are missing.")

            end_time = time.time()
            response_time = end_time - start_time
            st.info(f"⏱️ Scan completed in **{response_time:.2f} seconds**.")
            logging.info(f"Scan completed: {url_input} - SQL Injection: {sql_injection} - XSS: {xss} - Response Time: {response_time:.2f}s")
            
            st.write("🔗 Scanning all URLs found on the website...")
            all_urls = find_all_urls(url_input, soup)
            if all_urls:
                st.write(f"📑 Found **{len(all_urls)}** URLs on the site.")
                for sub_url in all_urls:
                    with st.expander(f"🔐 Scan Results for **{sub_url}**"):
                        st.write(f"🔍 Scanning {sub_url}...")
                        sub_soup, sub_headers, sub_response = scan_website(sub_url)
                        if isinstance(sub_soup, BeautifulSoup):
                            sub_sql_injection = detect_sql_injection(sub_url)
                            sub_xss = detect_xss(sub_url)
                            sub_header_issues = check_headers(sub_headers)
                            sub_suggestions = give_suggestions(sub_sql_injection, sub_xss, sub_headers)
                            
                            if sub_sql_injection:
                                st.warning(f"🚨 **Potential SQL Injection detected in {sub_url}!**")
                            if sub_xss:
                                st.warning(f"🚨 **Potential XSS vulnerability in {sub_url}!**")
                            if sub_header_issues:
                                st.error(f"❌ **Issues with headers in {sub_url}:**")
                                for issue in sub_header_issues:
                                    st.write(f"- {issue}")
                            if sub_suggestions:
                                st.warning(f"💡 **Recommendations for {sub_url}:**")
                                for suggestion in sub_suggestions:
                                    st.write(f"- {suggestion}")
                st.info("🔍 Finished scanning all URLs.")
    else:
        st.error("❌ Could not fetch the website. Please check the URL.")
