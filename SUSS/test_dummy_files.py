import os
import tempfile
import shutil
from client_test import ScannerClient

def create_dummy_files(temp_dir):
    """Create dummy files in a temporary directory structure"""
    # Create subdirectories
    os.makedirs(os.path.join(temp_dir, "subdir1"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "subdir2"), exist_ok=True)
    
    # Create dummy files with different content
    dummy_files = {
        "file1.txt": b"This is dummy file 1 with some test content.",
        "file2.bin": b"\x00\x01\x02\x03\x04\x05 Binary dummy file",
        "subdir1/nested1.txt": b"Nested file 1 in subdirectory",
        "subdir1/nested2.bin": b"\xFF\xFE\xFD\xFC Binary nested file",
        "subdir2/deep_file.txt": b"Another deeply nested test file with more content to test chunking",
    }
    
    for rel_path, content in dummy_files.items():
        file_path = os.path.join(temp_dir, rel_path)
        with open(file_path, "wb") as f:
            f.write(content)
        print(f"Created: {rel_path} ({len(content)} bytes)")

def main():
    """Main test function"""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="scanner_test_")
    print(f"\nCreated temporary directory: {temp_dir}\n")
    
    try:
        # Create dummy files
        print("Creating dummy files...")
        create_dummy_files(temp_dir)
        
        # Initialize the scanner client
        print("\nInitializing scanner client...")
        client = ScannerClient(server_address="localhost:50051")
        
        # Scan the temporary directory
        print("Scanning directory...\n")
        results = client.scan_directory(temp_dir)
        
        print(f"\nScan completed. Results: {len(results)} responses received")
        for result in results:
            print(f"  - {result.path_within_directory}: {result.status}")
            
    except Exception as e:
        print(f"Error during test: {e}")
    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir)
        print(f"\nCleaned up temporary directory: {temp_dir}")

if __name__ == "__main__":
    main()
