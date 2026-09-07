import re
import string

try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.stem import PorterStemmer
    from nltk.tokenize import word_tokenize
    STOP_WORDS = set(stopwords.words('english'))
    STEMMER = PorterStemmer()
except Exception:
    # Built-in fallback stopwords if NLTK is not initialized
    STOP_WORDS = {
        'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', "you're", "you've",
        "you'll", "you'd", 'your', 'yours', 'yourself', 'yourselves', 'he', 'him', 'his',
        'himself', 'she', "she's", 'her', 'hers', 'herself', 'it', "it's", 'its', 'itself',
        'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom',
        'this', 'that', "that'll", 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be',
        'been', 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a',
        'an', 'the', 'and', 'but', 'if', 'or', 'because', 'as', 'until', 'while', 'of', 'at',
        'by', 'for', 'with', 'about', 'against', 'between', 'into', 'through', 'during', 'before',
        'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out', 'on', 'off', 'over',
        'under', 'again', 'further', 'then', 'once'
    }
    STEMMER = None

# Reputable mainstream domains widely shared in normal personal conversations
SAFE_DOMAINS = [
    'youtube.com', 'youtu.be', 'google.com', 'docs.google.com', 'drive.google.com',
    'github.com', 'wikipedia.org', 'linkedin.com', 'instagram.com', 'spotify.com',
    'twitter.com', 'x.com', 'medium.com', 'stackoverflow.com', 'zoom.us', 'meet.google.com'
]

def replace_url_token(match):
    url_str = match.group(0).lower()
    if any(sd in url_str for sd in SAFE_DOMAINS):
        return ' safelinktoken '
    return ' httpurl '

def clean_text(text):
    """
    Standard text preprocessing:
    1. Lowercase
    2. Normalize URLs (distinguishing known safe platforms from unknown links)
    3. Remove punctuation & numbers
    4. Tokenize & remove stop words
    5. Stemming
    """
    if not text or not isinstance(text, str):
        return ""

    text = text.lower()

    # Replace URLs with differentiated tokens
    text = re.sub(r'https?://\S+|www\.\S+', replace_url_token, text)

    # Remove emails
    text = re.sub(r'\S+@\S+', ' emailtoken ', text)

    # Remove non-alphabet characters
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)

    # Tokenize
    words = text.split()

    # Filter stopwords and short tokens
    cleaned = []
    for w in words:
        if w not in STOP_WORDS and len(w) > 1:
            if STEMMER:
                cleaned.append(STEMMER.stem(w))
            else:
                cleaned.append(w)

    return " ".join(cleaned)

if __name__ == '__main__':
    sample = "CONGRATULATIONS!!! You WON $1000 in lottery. Click HERE: https://example.com/prize"
    print("Cleaned:", clean_text(sample))
