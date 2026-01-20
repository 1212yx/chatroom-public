import zipfile
import os
import shutil

# Paths
base_dir = os.getcwd()
dist_dir = os.path.join(base_dir, 'dist')
static_lib_dir = os.path.join(base_dir, 'static', 'lib')

# Create static/lib directory
if not os.path.exists(static_lib_dir):
    os.makedirs(static_lib_dir)

# Function to unzip
def unzip_file(zip_name, target_name):
    zip_path = os.path.join(dist_dir, zip_name)
    target_path = os.path.join(static_lib_dir, target_name)
    
    if os.path.exists(target_path):
        print(f"{target_name} already exists, skipping...")
        return

    print(f"Unzipping {zip_name}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(static_lib_dir)
            
            # Handle if the zip extracts to a folder with a version number or different name
            extracted_folders = [f for f in os.listdir(static_lib_dir) if os.path.isdir(os.path.join(static_lib_dir, f)) and f != target_name and f not in ['bootstrap', 'fontawesome', 'jquery']]
            
            # This logic is a bit loose, let's look at what we extracted.
            # For this specific task, I'll just extract and then we can rename if needed.
            # But to be safe, let's just extract to a temp dir and move.
            pass
    except Exception as e:
        print(f"Error unzipping {zip_name}: {e}")

# Unzip Bootstrap
print("Processing Bootstrap...")
with zipfile.ZipFile(os.path.join(dist_dir, 'bootstrap.zip'), 'r') as z:
    # Get top level folder name
    top_level = {item.split('/')[0] for item in z.namelist() if '/' in item}
    z.extractall(static_lib_dir)
    
    # Rename if necessary or just note the path
    # Assuming standard bootstrap zip structure
    print(f"Extracted Bootstrap. Top level folders: {top_level}")

# Unzip FontAwesome
print("Processing FontAwesome...")
with zipfile.ZipFile(os.path.join(dist_dir, 'fontawesome-free-6.4.0-web.zip'), 'r') as z:
    z.extractall(static_lib_dir)
    print("Extracted FontAwesome.")

# Copy jQuery
print("Processing jQuery...")
jquery_src = os.path.join(dist_dir, 'jquery-3.5.1.min.js')
jquery_dest_dir = os.path.join(static_lib_dir, 'jquery')
if not os.path.exists(jquery_dest_dir):
    os.makedirs(jquery_dest_dir)
shutil.copy(jquery_src, jquery_dest_dir)
print("Copied jQuery.")
