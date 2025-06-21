import requests
import unittest
import uuid
import time
from datetime import datetime

# Get the backend URL from the frontend .env file
BACKEND_URL = "https://fc8e6737-f906-4400-bfd6-e1c7562ef7ca.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

class VNCManagementAPITest(unittest.TestCase):
    def setUp(self):
        # Create a unique test connection for testing
        self.test_connection_name = f"Test Connection {uuid.uuid4().hex[:8]}"
        self.test_connection_data = {
            "name": self.test_connection_name,
            "location": "Test Lab",
            "country": "Russia",
            "city": "Moscow"
        }
        
        # Create a test connection
        response = requests.post(f"{API_URL}/connections", json=self.test_connection_data)
        self.assertEqual(response.status_code, 200, "Failed to create test connection")
        self.test_connection = response.json()
        self.connection_id = self.test_connection["id"]
        print(f"Created test connection with ID: {self.connection_id}")

    def tearDown(self):
        # Clean up - delete the test connection
        try:
            requests.delete(f"{API_URL}/connections/{self.connection_id}")
            print(f"Deleted test connection with ID: {self.connection_id}")
        except Exception as e:
            print(f"Error deleting test connection: {e}")

    def test_health_endpoint(self):
        """Test the health check endpoint"""
        response = requests.get(f"{API_URL}/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("timestamp", data)
        print("✅ Health endpoint test passed")

    def test_get_connections(self):
        """Test getting all connections"""
        response = requests.get(f"{API_URL}/connections")
        self.assertEqual(response.status_code, 200)
        connections = response.json()
        self.assertIsInstance(connections, list)
        # Verify our test connection is in the list
        connection_ids = [conn["id"] for conn in connections]
        self.assertIn(self.connection_id, connection_ids)
        print("✅ Get connections test passed")

    def test_get_connection_by_id(self):
        """Test getting a specific connection by ID"""
        response = requests.get(f"{API_URL}/connections/{self.connection_id}")
        self.assertEqual(response.status_code, 200)
        connection = response.json()
        self.assertEqual(connection["id"], self.connection_id)
        self.assertEqual(connection["name"], self.test_connection_name)
        print("✅ Get connection by ID test passed")

    def test_generate_installer(self):
        """Test generating a PowerShell installer"""
        response = requests.get(f"{API_URL}/generate-installer/{self.connection_id}")
        self.assertEqual(response.status_code, 200)
        # Check that we got a PowerShell script
        self.assertTrue(response.text.startswith("# VNC Auto-Installation Script"))
        self.assertIn(self.test_connection["installation_key"], response.text)
        print("✅ Generate installer test passed")

    def test_register_machine(self):
        """Test registering a machine after installation"""
        registration_data = {
            "installation_key": self.test_connection["installation_key"],
            "machine_name": f"Test Machine {uuid.uuid4().hex[:8]}",
            "ip_address": "192.168.1.123",
            "status": "active"
        }
        
        response = requests.post(f"{API_URL}/register-machine", json=registration_data)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["message"], "Machine registered successfully")
        self.assertEqual(data["connection_id"], self.connection_id)
        
        # Verify the connection status was updated
        response = requests.get(f"{API_URL}/connections/{self.connection_id}")
        connection = response.json()
        self.assertEqual(connection["status"], "active")
        self.assertEqual(connection["ip_address"], "192.168.1.123")
        print("✅ Register machine test passed")

    def test_stats_endpoint(self):
        """Test the statistics endpoint"""
        response = requests.get(f"{API_URL}/stats")
        self.assertEqual(response.status_code, 200)
        stats = response.json()
        self.assertIn("total_connections", stats)
        self.assertIn("active_connections", stats)
        self.assertIn("inactive_connections", stats)
        self.assertIn("recent_activity_24h", stats)
        self.assertIn("timestamp", stats)
        print("✅ Stats endpoint test passed")

    def test_files_listing(self):
        """Test listing files for a connection"""
        # First, register the machine to make it active
        registration_data = {
            "installation_key": self.test_connection["installation_key"],
            "machine_name": f"Test Machine {uuid.uuid4().hex[:8]}",
            "ip_address": "192.168.1.123",
            "status": "active"
        }
        requests.post(f"{API_URL}/register-machine", json=registration_data)
        
        # Now test file listing
        response = requests.get(f"{API_URL}/files/{self.connection_id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["connection_id"], self.connection_id)
        self.assertIn("files", data)
        self.assertIsInstance(data["files"], list)
        print("✅ Files listing test passed")

    def test_vnc_screenshot(self):
        """Test getting a VNC screenshot"""
        # First, register the machine to make it active
        registration_data = {
            "installation_key": self.test_connection["installation_key"],
            "machine_name": f"Test Machine {uuid.uuid4().hex[:8]}",
            "ip_address": "192.168.1.123",
            "status": "active"
        }
        requests.post(f"{API_URL}/register-machine", json=registration_data)
        
        # Now test screenshot
        response = requests.get(f"{API_URL}/vnc/{self.connection_id}/screenshot")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "image/svg+xml")
        self.assertIn("<svg", response.text)
        print("✅ VNC screenshot test passed")

    def test_system_info(self):
        """Test getting system information"""
        response = requests.get(f"{API_URL}/system/info")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("vnc_management_version", data)
        self.assertIn("system_time", data)
        self.assertIn("features", data)
        print("✅ System info test passed")

if __name__ == "__main__":
    unittest.main(verbosity=2)