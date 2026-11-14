import unittest
from predictor import analyze_message

class PredictorTests(unittest.TestCase):
    def test_message_result_shape_and_range(self):
        result = analyze_message("Hello, are we meeting tomorrow?")
        self.assertIn("prediction", result)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_empty_message_rejected(self):
        with self.assertRaises(ValueError):
            analyze_message(" ")

if __name__ == "__main__":
    unittest.main()
