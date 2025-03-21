import os
import argparse
import boto3
from google.cloud import storage
from azure.storage.blob import BlobServiceClient


def upload_to_s3(bucket_name, file_path, object_name=None):
    s3 = boto3.client('s3')
    if object_name is None:
        object_name = os.path.basename(file_path)

    try:
        s3.upload_file(file_path, bucket_name, object_name)
        print(f"Uploaded {file_path} to S3 bucket {bucket_name}/{object_name}")
    except Exception as e:
        print(f"Error uploading to S3: {e}")


def upload_to_gcp(bucket_name, file_path, object_name=None):
    try:
        # GCP uses GOOGLE_APPLICATION_CREDENTIALS env var or default service account if on GCP
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name or os.path.basename(file_path))

        blob.upload_from_filename(file_path)
        print(f"Uploaded {file_path} to GCP bucket {bucket_name}/{blob.name}")
    except Exception as e:
        print(f"Error uploading to GCP: {e}")


def upload_to_azure(container_name, file_path, object_name=None):
    try:
        connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if not connect_str:
            raise ValueError("AZURE_STORAGE_CONNECTION_STRING environment variable not set")

        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        blob_client = blob_service_client.get_blob_client(
            container=container_name,
            blob=object_name or os.path.basename(file_path)
        )

        with open(file_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True)
        print(f"Uploaded {file_path} to Azure container {container_name}/{blob_client.blob_name}")
    except Exception as e:
        print(f"Error uploading to Azure: {e}")


def upload_file(provider, bucket_or_container_name, file_path, object_name=None):
    if provider == 's3':
        upload_to_s3(bucket_or_container_name, file_path, object_name)
    elif provider == 'gcp':
        upload_to_gcp(bucket_or_container_name, file_path, object_name)
    elif provider == 'azure':
        upload_to_azure(bucket_or_container_name, file_path, object_name)
    else:
        print("Unsupported provider. Use 's3', 'gcp', or 'azure'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Upload a file to AWS S3, GCP, or Azure Blob Storage.")
    parser.add_argument("file", help="Path to the file to upload")
    parser.add_argument("bucket_or_container", help="Bucket name for S3/GCP or container name for Azure")
    parser.add_argument("--object-name", help="Optional destination name in the bucket/container")

    provider_group = parser.add_mutually_exclusive_group(required=True)
    provider_group.add_argument("--aws", action="store_true", help="Use AWS S3")
    provider_group.add_argument("--gcp", action="store_true", help="Use Google Cloud Storage")
    provider_group.add_argument("--azure", action="store_true", help="Use Azure Blob Storage")

    args = parser.parse_args()

    provider = 's3' if args.aws else 'gcp' if args.gcp else 'azure'
    upload_file(provider, args.bucket_or_container, args.file, args.object_name)
