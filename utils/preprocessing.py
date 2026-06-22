# preprocessing/preprocessing.py
# Text cleaning utility used by keyword engine and ML model

import re

def clean_text(text):
    """
    Cleans raw text before ML prediction or keyword scanning.
    - Converts to lowercase
    - Removes punctuation
    - Collapses extra spaces
    """
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text
