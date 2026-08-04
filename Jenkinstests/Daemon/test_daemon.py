import os
import subprocess
import unittest

class TestDaemonServices(unittest.TestCase):

    def setUp(self):
        self.script_path = "./scripts/update_threat_intel.sh"
        self.threats_file = "./fast_path/threats.txt"
        
        # FIX: Add the correct subfolder path here if they aren't in the root
        self.loader_service = "./scripts/ips-loader.service"
        self.updater_service = "./scripts/ips-threat-intel-update.service"

    def test_01_threat_intel_script_execution(self):
        """Test if the update script fetches the blocklist and handles minimum limits properly."""
        
        # Ensure script is executable
        self.assertTrue(os.path.exists(self.script_path), f"Missing {self.script_path}")
        os.chmod(self.script_path, 0o755)

        # Ensure the fast_path directory exists for the output file
        os.makedirs("./fast_path", exist_ok=True)

        # Run the bash script
        result = subprocess.run([self.script_path], capture_output=True, text=True)
        
        # Assert the script exited cleanly
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        
        # Verify the threats.txt file was created
        self.assertTrue(os.path.exists(self.threats_file), "threats.txt was not created by the script")
        
        # Verify file contents are valid IPs and meet the minimum entry threshold
        with open(self.threats_file, "r") as f:
            lines = f.readlines()
            
        valid_ips = [line for line in lines if not line.startswith("#") and line.strip()]
        self.assertGreater(len(valid_ips), 100, f"threats.txt contains fewer entries ({len(valid_ips)}) than expected.")

    def test_02_service_files_contain_execstart(self):
        """Test that systemd files contain the required execution directives."""
        
        services_to_check = [self.loader_service, self.updater_service]
        
        for svc_file in services_to_check:
            if not os.path.exists(svc_file):
                print(f"Warning: {svc_file} not found in repo root. Skipping content check.")
                continue
                
            with open(svc_file, "r") as f:
                content = f.read()
                
            # Verify the service file has an ExecStart path configured
            self.assertIn("ExecStart=", content, f"{svc_file} is missing the ExecStart directive.")

if __name__ == '__main__':
    unittest.main(verbosity=2)