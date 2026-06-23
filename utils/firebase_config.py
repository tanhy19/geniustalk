# utils/firebase_config.py
# Firebase REST API helper
# No SDK needed — pure HTTP requests, works everywhere

import requests
import json
import os
from datetime import datetime

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

import os

FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "your-project-id-here")
FIREBASE_API_KEY    = os.environ.get("FIREBASE_API_KEY", "your-api-key-here")

# Firestore base URL
FIRESTORE_URL = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents"

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _to_firestore_value(value):
    """Converts Python value to Firestore REST format."""
    if value is None:
        return {"nullValue": None}
    elif isinstance(value, bool):
        return {"booleanValue": value}
    elif isinstance(value, int):
        return {"integerValue": str(value)}
    elif isinstance(value, float):
        return {"doubleValue": value}
    elif isinstance(value, str):
        return {"stringValue": value}
    elif isinstance(value, list):
        return {"arrayValue": {"values": [_to_firestore_value(v) for v in value]}}
    elif isinstance(value, dict):
        return {"mapValue": {"fields": {k: _to_firestore_value(v) for k, v in value.items()}}}
    else:
        return {"stringValue": str(value)}


def _from_firestore_value(value):
    """Converts Firestore REST value to Python."""
    if "nullValue" in value:
        return None
    elif "booleanValue" in value:
        return value["booleanValue"]
    elif "integerValue" in value:
        return int(value["integerValue"])
    elif "doubleValue" in value:
        return float(value["doubleValue"])
    elif "stringValue" in value:
        return value["stringValue"]
    elif "arrayValue" in value:
        return [_from_firestore_value(v) for v in value["arrayValue"].get("values", [])]
    elif "mapValue" in value:
        return {k: _from_firestore_value(v) for k, v in value["mapValue"].get("fields", {}).items()}
    return None


def _doc_to_dict(doc):
    """Converts Firestore document to Python dict."""
    fields = doc.get("fields", {})
    return {k: _from_firestore_value(v) for k, v in fields.items()}


def _dict_to_fields(data):
    """Converts Python dict to Firestore fields format."""
    return {k: _to_firestore_value(v) for k, v in data.items()}


# ─────────────────────────────────────────
# CORE OPERATIONS
# ─────────────────────────────────────────

def add_document(collection, data):
    """Adds a document to a Firestore collection."""
    try:
        url      = f"{FIRESTORE_URL}/{collection}"
        payload  = {"fields": _dict_to_fields(data)}
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code in (200, 201):
            doc = response.json()
            # Extract document ID from name field
            doc_id = doc.get("name", "").split("/")[-1]
            return doc_id
        return None
    except Exception as e:
        print(f"add_document error: {e}")
        return None


def set_document(collection, doc_id, data, merge=False):
    """Sets a document (creates or overwrites)."""
    try:
        url     = f"{FIRESTORE_URL}/{collection}/{doc_id}"
        payload = {"fields": _dict_to_fields(data)}
        if merge:
            # Use PATCH for merge
            response = requests.patch(url, json=payload, timeout=10)
        else:
            response = requests.patch(url, json=payload, timeout=10)
        return response.status_code in (200, 201)
    except Exception as e:
        print(f"set_document error: {e}")
        return False


def get_document(collection, doc_id):
    """Gets a single document."""
    try:
        url      = f"{FIRESTORE_URL}/{collection}/{doc_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return _doc_to_dict(response.json())
        return None
    except Exception as e:
        print(f"get_document error: {e}")
        return None


def update_document(collection, doc_id, data):
    """Updates specific fields in a document."""
    try:
        url      = f"{FIRESTORE_URL}/{collection}/{doc_id}"
        # Build update mask
        fields   = list(data.keys())
        mask     = "&".join([f"updateMask.fieldPaths={f}" for f in fields])
        url      = f"{url}?{mask}"
        payload  = {"fields": _dict_to_fields(data)}
        response = requests.patch(url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"update_document error: {e}")
        return False

def query_collection(collection, filters=None, order_by=None, limit=50):
    """
    Queries a collection with optional filters.
    Note: Cannot combine filters + order_by without Firestore indexes.
    When filters are provided, ordering is done in Python instead.
    """
    try:
        url = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents:runQuery"

        # Build structured query
        query = {
            "from" : [{"collectionId": collection}],
            "limit": limit
        }

        # Add filters
        if filters:
            field_filters = []
            for field, op, value in filters:
                field_filters.append({
                    "fieldFilter": {
                        "field": {"fieldPath": field},
                        "op"   : op,
                        "value": _to_firestore_value(value)
                    }
                })

            if len(field_filters) == 1:
                query["where"] = field_filters[0]
            else:
                query["where"] = {
                    "compositeFilter": {
                        "op"     : "AND",
                        "filters": field_filters
                    }
                }

            # When using filters, DON'T add orderBy
            # (requires composite index in Firestore)
            # We sort in Python instead after fetching

        elif order_by:
            # Only add orderBy when there are NO filters
            query["orderBy"] = [{
                "field"    : {"fieldPath": order_by},
                "direction": "DESCENDING"
            }]

        payload  = {"structuredQuery": query}
        response = requests.post(url, json=payload, timeout=15)

        if response.status_code == 200:
            results = []
            for item in response.json():
                if "document" in item:
                    doc    = item["document"]
                    doc_id = doc.get("name", "").split("/")[-1]
                    data   = _doc_to_dict(doc)
                    data["id"] = doc_id
                    results.append(data)

            # Sort in Python when filters were used
            if filters and order_by and results:
                results.sort(
                    key=lambda x: x.get(order_by, ''),
                    reverse=True
                )

            return results
        return []

    except Exception as e:
        print(f"query_collection error: {e}")
        return []


def increment_field(collection, doc_id, field, amount=1):
    """
    Increments a numeric field using Firestore transforms.
    Used for stats counters.
    """
    try:
        url = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/{collection}/{doc_id}?currentDocument.exists=true"

        payload = {
            "fields": {},
            "transforms": [
                {
                    "fieldPath": field,
                    "increment": {"integerValue": str(amount)}
                }
            ]
        }

        # Use the write API for transforms
        write_url = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents:commit"
        write_payload = {
            "writes": [
                {
                    "transform": {
                        "document"       : f"projects/{FIREBASE_PROJECT_ID}/databases/(default)/documents/{collection}/{doc_id}",
                        "fieldTransforms": [
                            {
                                "fieldPath": field,
                                "increment": {"integerValue": str(amount)}
                            }
                        ]
                    }
                }
            ]
        }

        response = requests.post(write_url, json=write_payload, timeout=10)
        return response.status_code == 200

    except Exception as e:
        print(f"increment_field error: {e}")
        return False