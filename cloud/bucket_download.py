import os
import json
import hashlib
import argparse
import boto3
from google.cloud import storage
from azure.storage.blob import BlobServiceClient

def compute_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def make_local_path(bucket_path, filename):
    safe_path = (bucket_path + filename).replace('/', '_')
    return os.path.join('data', 'cache', safe_path + '.json')

def load_hashes():
    if os.path.exists('data/hashes.json'):
        with open('data/hashes.json', 'r') as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    os.makedirs('data', exist_ok=True)
    with open('data/hashes.json', 'w') as f:
        json.dump(hashes, f, indent=2)

def download_from_s3(bucket_name, bucket_path, filename):
    s3 = boto3.client('s3')
    key = bucket_path + filename
    local_path = make_local_path(bucket_path, filename)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    s3.download_file(bucket_name, key, local_path)
    return local_path

def download_from_gcp(bucket_name, bucket_path, filename):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(bucket_path + filename)
    local_path = make_local_path(bucket_path, filename)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    blob.download_to_filename(local_path)
    return local_path

def download_from_azure(container_name, bucket_path, filename):
    connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    if not connect_str:
        raise ValueError("AZURE_STORAGE_CONNECTION_STRING environment variable not set")

    blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=bucket_path + filename)
    local_path = make_local_path(bucket_path, filename)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    with open(local_path, "wb") as f:
        download_stream = blob_client.download_blob()
        f.write(download_stream.readall())
    return local_path

def download_file(provider, bucket_or_container, bucket_path, filename):
    hashes = load_hashes()
    hash_key = (bucket_path + filename).replace('/', '_')
    local_path = make_local_path(bucket_path, filename)

    # Skip download if we already have it with same hash
    if os.path.exists(local_path) and hash_key in hashes:
        current_hash = compute_sha256(local_path)
        if current_hash == hashes[hash_key]:
            print(f"File already exists and hash matches: {local_path}")
            return

    if provider == 's3':
        path = download_from_s3(bucket_or_container, bucket_path, filename)
    elif provider == 'gcp':
        path = download_from_gcp(bucket_or_container, bucket_path, filename)
    elif provider == 'azure':
        path = download_from_azure(bucket_or_container, bucket_path, filename)
    else:
        raise ValueError("Unsupported provider. Use 's3', 'gcp', or 'azure'.")

    # Save new hash
    hashes[hash_key] = compute_sha256(path)
    save_hashes(hashes)
    print(f"Downloaded to {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download a file from AWS S3, GCP, or Azure Blob Storage with caching.")
    parser.add_argument("--bucket", required=True, help="Bucket name for S3/GCP or container name for Azure")
    parser.add_argument("--bucket_path", required=True, help="Path within the bucket")
    parser.add_argument("--filename", required=True, help="Name of the file to download")

    provider_group = parser.add_mutually_exclusive_group(required=True)
    provider_group.add_argument("--aws", action="store_true", help="Use AWS S3")
    provider_group.add_argument("--gcp", action="store_true", help="Use Google Cloud Storage")
    provider_group.add_argument("--azure", action="store_true", help="Use Azure Blob Storage")

    args = parser.parse_args()
    provider = 's3' if args.aws else 'gcp' if args.gcp else 'azure'

    download_file(provider, args.bucket, args.bucket_path, args.filename)
