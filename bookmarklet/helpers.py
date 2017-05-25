try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

def check_if_wikipedia_link(str):
    if 'wikipedia' in str:
        return True
    return False

def update_wikipedia_link(string):
    if check_if_wikipedia_link(string):
        if not string.startswith('https://en.m.wiki'):
            urlparsed = urlparse(string)
            return urlparsed.scheme + "://" + "en.m.wikipedia.org" + urlparsed.path
    return string

