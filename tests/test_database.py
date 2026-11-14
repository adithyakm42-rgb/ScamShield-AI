import tempfile
import unittest
from pathlib import Path
import database

class DatabaseTests(unittest.TestCase):
    def test_save_read_and_clear(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "test.db"
            database.create_table(db)
            database.save_scan("URL", "https://example.com", "Review", 20, db)
            rows = database.get_all_scans(db)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], "URL")
            self.assertEqual(rows[0][2], "https://example.com")
            database.clear_history(db)
            self.assertEqual(database.get_all_scans(db), [])

if __name__ == "__main__":
    unittest.main()
