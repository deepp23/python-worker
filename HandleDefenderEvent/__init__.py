import logging
import json
import time
import azure.functions as func
from azure.storage.blob import BlobServiceClient, BlobClient
from azure.core.exceptions import ResourceNotFoundError, AzureError

def main(eventGridEvent: func.EventGridEvent):
    logging.info("🛡️ Defender Event Handler triggered!")
    
    try:
        # Get event data
        result = eventGridEvent.get_json()
        logging.info(f"📄 Event Type: {eventGridEvent.event_type}")
        logging.info(f"📍 Subject: {eventGridEvent.subject}")
        logging.info(f"📦 Event Data: {json.dumps(result, indent=2)}")
        
        # Extract blob URL from event data
        blob_url = extract_blob_url(result)
        if not blob_url:
            logging.warning("❌ Blob URL not found in event data")
            return
            
        logging.info(f"🔗 Processing blob: {blob_url}")
        
        # Process the blob based on scan results
        process_scanned_blob(blob_url, result)
        
        logging.info("✅ Event processed successfully!")
        
    except Exception as e:
        logging.error(f"❌ Error processing Defender event: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        raise

def extract_blob_url(event_data):
    """Extract blob URL from various possible event data structures"""
    
    # Try different possible paths where blob URL might be
    possible_paths = [
        ("data", "url"),
        ("data", "blobUrl"),
        ("data", "properties", "extendedProperties", "BlobUrl"),
        ("properties", "extendedProperties", "BlobUrl"),
        ("subject",),  # Sometimes the subject contains the blob path
    ]
    
    for path in possible_paths:
        try:
            value = event_data
            for key in path:
                value = value.get(key, {})
            
            if isinstance(value, str) and ("blob.core.windows.net" in value or "/blobs/" in value):
                return value
        except (AttributeError, TypeError):
            continue
    
    # If subject contains blob path, construct full URL
    subject = event_data.get("subject", "")
    if "/blobs/" in subject:
        # Extract storage account and container from subject
        # Subject format: /blobServices/default/containers/{container}/blobs/{blob}
        parts = subject.split("/")
        if len(parts) >= 6:
            container = parts[4]
            blob_name = "/".join(parts[6:])  # Handle blobs with / in name
            # Your storage account name
            storage_account = "mydocstorage123"
            return f"https://{storage_account}.blob.core.windows.net/{container}/{blob_name}"
    
    return None

def process_scanned_blob(blob_url, event_data):
    """Process blob based on Defender scan results"""
    
    try:
        # Create blob client
        blob_client = BlobClient.from_blob_url(blob_url)
        
        # Get blob properties and metadata
        try:
            properties = blob_client.get_blob_properties()
            metadata = properties.metadata or {}
            
            doc_id = metadata.get("DocumentId", "Unknown")
            req_id = metadata.get("RequestId", "Unknown")
            
            logging.info(f"📋 DocumentId: {doc_id}")
            logging.info(f"🆔 RequestId: {req_id}")
            
        except ResourceNotFoundError:
            logging.warning(f"⚠️ Blob not found: {blob_url}")
            return
            
        # Analyze scan results
        scan_result = analyze_scan_result(event_data)
        logging.info(f"🔍 Scan Result: {scan_result}")
        
        if scan_result == "CLEAN":
            move_to_clean_storage(blob_client, blob_url)
        elif scan_result == "MALWARE":
            delete_malware(blob_client, blob_url)
        else:
            logging.info("❓ Unknown scan result - no action taken")
            
    except Exception as e:
        logging.error(f"❌ Error processing blob {blob_url}: {str(e)}")
        raise

def analyze_scan_result(event_data):
    """Analyze event data to determine scan result"""
    
    # Get description from various possible locations
    description = ""
    
    # Try different paths for description/result
    possible_desc_paths = [
        ("data", "description"),
        ("data", "properties", "description"),
        ("properties", "description"),
        ("data", "scanResult"),
        ("data", "verdict"),
    ]
    
    for path in possible_desc_paths:
        try:
            value = event_data
            for key in path:
                value = value.get(key, "")
            if isinstance(value, str) and value:
                description = value.lower()
                break
        except (AttributeError, TypeError):
            continue
    
    logging.info(f"📝 Scan Description: {description}")
    
    # Analyze description for threats
    if any(clean_indicator in description for clean_indicator in 
           ["no threats found", "clean", "safe", "no malware"]):
        return "CLEAN"
    elif any(threat_indicator in description for threat_indicator in 
             ["malware", "virus", "threat", "infected", "suspicious"]):
        return "MALWARE"
    else:
        return "UNKNOWN"

def move_to_clean_storage(source_blob_client, source_url):
    """Move clean file from quarantined to clean container"""
    
    try:
        # Create destination URL (change container from quarantined to clean)
        clean_url = source_url.replace("quarantined", "clean")
        dest_blob_client = BlobClient.from_blob_url(clean_url)
        
        logging.info(f"📤 Moving clean file to: {clean_url}")
        
        # Start copy operation
        copy_operation = dest_blob_client.start_copy_from_url(source_url)
        
        # Wait for copy to complete (with timeout)
        timeout = 300  # 5 minutes
        start_time = time.time()
        
        while copy_operation.get('copy_status') != 'success':
            if time.time() - start_time > timeout:
                raise TimeoutError("Copy operation timed out")
                
            time.sleep(2)
            try:
                props = dest_blob_client.get_blob_properties()
                copy_operation = props.copy
            except Exception:
                break
        
        logging.info("✅ File copied to clean container successfully")
        
        # Delete source blob from quarantined after successful copy
        source_blob_client.delete_blob()
        logging.info("🗑️ Source blob deleted from quarantined container")
        
    except Exception as e:
        logging.error(f"❌ Error moving file to clean storage: {str(e)}")
        raise

def delete_malware(blob_client, blob_url):
    """Delete malware file from quarantined container"""
    
    try:
        logging.warning(f"🦠 MALWARE DETECTED in: {blob_url}")
        
        # Delete the malware file from quarantined container
        blob_client.delete_blob()
        logging.warning("🗑️ Malware file deleted from quarantined container")
        
    except Exception as e:
        logging.error(f"❌ Error deleting malware: {str(e)}")
        raise