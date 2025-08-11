import re
import whois
import dns.resolver
import requests
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import pandas as pd
import numpy as np

# This list must match the column order of the training data
FEATURE_NAMES = [
    'qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url', 'qty_questionmark_url',
    'qty_equal_url', 'qty_at_url', 'qty_and_url', 'qty_exclamation_url', 'qty_space_url',
    'qty_tilde_url', 'qty_comma_url', 'qty_plus_url', 'qty_asterisk_url', 'qty_hashtag_url',
    'qty_dollar_url', 'qty_percent_url', 'qty_tld_url', 'length_url', 'qty_dot_domain',
    'qty_hyphen_domain', 'qty_underline_domain', 'qty_slash_domain', 'qty_questionmark_domain',
    'qty_equal_domain', 'qty_at_domain', 'qty_and_domain', 'qty_exclamation_domain',
    'qty_space_domain', 'qty_tilde_domain', 'qty_comma_domain', 'qty_plus_domain',
    'qty_asterisk_domain', 'qty_hashtag_domain', 'qty_dollar_domain', 'qty_percent_domain',
    'qty_vowels_domain', 'domain_length', 'domain_in_ip', 'server_client_domain',
    'qty_dot_directory', 'qty_hyphen_directory', 'qty_underline_directory', 'qty_slash_directory',
    'qty_questionmark_directory', 'qty_equal_directory', 'qty_at_directory', 'qty_and_directory',
    'qty_exclamation_directory', 'qty_space_directory', 'qty_tilde_directory',
    'qty_comma_directory', 'qty_plus_directory', 'qty_asterisk_directory', 'qty_hashtag_directory',
    'qty_dollar_directory', 'qty_percent_directory', 'directory_length', 'qty_dot_file',
    'qty_hyphen_file', 'qty_underline_file', 'qty_slash_file', 'qty_questionmark_file',
    'qty_equal_file', 'qty_at_file', 'qty_and_file', 'qty_exclamation_file', 'qty_space_file',
    'qty_tilde_file', 'qty_comma_file', 'qty_plus_file', 'qty_asterisk_file',
    'qty_hashtag_file', 'qty_dollar_file', 'qty_percent_file', 'file_length',
    'qty_dot_params', 'qty_hyphen_params', 'qty_underline_params', 'qty_slash_params',
    'qty_questionmark_params', 'qty_equal_params', 'qty_at_params', 'qty_and_params',
    'qty_exclamation_params', 'qty_space_params', 'qty_tilde_params', 'qty_comma_params',
    'qty_plus_params', 'qty_asterisk_params', 'qty_hashtag_params', 'qty_dollar_params',
    'qty_percent_params', 'params_length', 'tld_present_params', 'qty_params', 'email_in_url',
    'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation',
    'time_domain_expiration', 'qty_ip_resolved', 'qty_nameservers', 'qty_mx_servers',
    'ttl_hostname', 'tls_ssl_certificate', 'qty_redirects', 'url_google_index',
    'domain_google_index', 'url_shortened'
]


def extract_features_from_url(url):
    """
    Extracts 111 features from a given URL.
    Returns a pandas DataFrame with a single row.
    """
    features = {}

    # --- URL-based Features ---
    parsed_url = urlparse(url)
    full_url_str = url
    domain_str = parsed_url.netloc
    directory_str = parsed_url.path
    file_str = directory_str.split('/')[-1]
    params_str = parsed_url.query

    # Character counts in the full URL
    for char in ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']:
        features[f'qty_{char}_url'.replace(char, {'.': 'dot', '-': 'hyphen', '_': 'underline', '/': 'slash', '?': 'questionmark', '=': 'equal', '@': 'at', '&': 'and', '!': 'exclamation', ' ': 'space', '~': 'tilde', ',': 'comma', '+': 'plus', '*': 'asterisk', '#': 'hashtag', '$': 'dollar', '%': 'percent'}[char])] = full_url_str.count(char)
    
    ext = tldextract.extract(url)
    features['qty_tld_url'] = 1 if ext.suffix else 0
    features['length_url'] = len(full_url_str)

    # --- Domain-based Features ---
    for char in ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']:
        features[f'qty_{char}_domain'.replace(char, {'.': 'dot', '-': 'hyphen', '_': 'underline', '/': 'slash', '?': 'questionmark', '=': 'equal', '@': 'at', '&': 'and', '!': 'exclamation', ' ': 'space', '~': 'tilde', ',': 'comma', '+': 'plus', '*': 'asterisk', '#': 'hashtag', '$': 'dollar', '%': 'percent'}[char])] = domain_str.count(char)
    
    features['qty_vowels_domain'] = sum(1 for char in domain_str if char in 'aeiouAEIOU')
    features['domain_length'] = len(domain_str)
    features['domain_in_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_str) else 0
    features['server_client_domain'] = 1 if 'server' in domain_str.lower() or 'client' in domain_str.lower() else 0

    # --- Directory-based Features ---
    for char in ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']:
        features[f'qty_{char}_directory'.replace(char, {'.': 'dot', '-': 'hyphen', '_': 'underline', '/': 'slash', '?': 'questionmark', '=': 'equal', '@': 'at', '&': 'and', '!': 'exclamation', ' ': 'space', '~': 'tilde', ',': 'comma', '+': 'plus', '*': 'asterisk', '#': 'hashtag', '$': 'dollar', '%': 'percent'}[char])] = directory_str.count(char)
    features['directory_length'] = len(directory_str)

    # --- File-based Features ---
    for char in ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']:
        features[f'qty_{char}_file'.replace(char, {'.': 'dot', '-': 'hyphen', '_': 'underline', '/': 'slash', '?': 'questionmark', '=': 'equal', '@': 'at', '&': 'and', '!': 'exclamation', ' ': 'space', '~': 'tilde', ',': 'comma', '+': 'plus', '*': 'asterisk', '#': 'hashtag', '$': 'dollar', '%': 'percent'}[char])] = file_str.count(char)
    features['file_length'] = len(file_str)

    # --- Parameters-based Features ---
    for char in ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']:
        features[f'qty_{char}_params'.replace(char, {'.': 'dot', '-': 'hyphen', '_': 'underline', '/': 'slash', '?': 'questionmark', '=': 'equal', '@': 'at', '&': 'and', '!': 'exclamation', ' ': 'space', '~': 'tilde', ',': 'comma', '+': 'plus', '*': 'asterisk', '#': 'hashtag', '$': 'dollar', '%': 'percent'}[char])] = params_str.count(char)
    features['params_length'] = len(params_str)
    features['tld_present_params'] = 1 if tldextract.extract(params_str).suffix else 0
    features['qty_params'] = len(params_str.split('&')) if params_str else 0

    # --- External Lookups ---
    features['email_in_url'] = 1 if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url) else 0
    
    try:
        response = requests.get(url, timeout=3)
        features['time_response'] = response.elapsed.total_seconds()
        features['qty_redirects'] = len(response.history)
        features['tls_ssl_certificate'] = 1 if url.startswith('https') else 0
    except requests.exceptions.RequestException:
        features['time_response'] = -1
        features['qty_redirects'] = -1
        features['tls_ssl_certificate'] = -1

    try:
        domain_info = whois.whois(domain_str)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            features['time_domain_activation'] = (datetime.now() - creation_date).days
        else:
            features['time_domain_activation'] = -1
        
        if domain_info.expiration_date:
            expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
            features['time_domain_expiration'] = (expiration_date - datetime.now()).days
        else:
            features['time_domain_expiration'] = -1
    except (whois.parser.PywhoisError, TypeError):
        features['time_domain_activation'] = -1
        features['time_domain_expiration'] = -1

    try:
        answers = dns.resolver.resolve(domain_str, 'A')
        features['qty_ip_resolved'] = len(answers)
        features['ttl_hostname'] = answers.rrset.ttl
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        features['qty_ip_resolved'] = -1
        features['ttl_hostname'] = -1

    try:
        answers = dns.resolver.resolve(domain_str, 'NS')
        features['qty_nameservers'] = len(answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        features['qty_nameservers'] = -1

    try:
        answers = dns.resolver.resolve(domain_str, 'MX')
        features['qty_mx_servers'] = len(answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        features['qty_mx_servers'] = -1

    try:
        txt_records = dns.resolver.resolve(domain_str, 'TXT')
        features['domain_spf'] = 1 if any('v=spf1' in str(r) for r in txt_records) else 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        features['domain_spf'] = -1

    # Placeholder features - require external APIs or complex logic
    features['asn_ip'] = -1  # Requires GeoIP database or service
    features['url_google_index'] = -1 # Requires Google Search API
    features['domain_google_index'] = -1 # Requires Google Search API
    features['url_shortened'] = 1 if domain_str in ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com'] else 0

    # Ensure all features are present and in the correct order
    final_features = {name: features.get(name, -1) for name in FEATURE_NAMES}

    return pd.DataFrame([final_features])