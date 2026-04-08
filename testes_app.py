import unittest
import pandas as pd
from column_detector import auto_map_columns, detect_column_type

class TestColumnDetection(unittest.TestCase):
    def test_ip_detection(self):
        df = pd.DataFrame({
            "col_1": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
            "col_2": ["A", "B", "C"]
        })
        type_res, conf = detect_column_type(df["col_1"])
        self.assertEqual(type_res, "ip")
        
        type_res_2, _ = detect_column_type(df["col_2"])
        self.assertEqual(type_res_2, "unknown")

    def test_auto_map_shuffled(self):
        # Nomes completamente zoados com dados reais
        df = pd.DataFrame({
            "Batata": [80, 443, 22, 3389],
            "Endereco": ["8.8.8.8", "1.1.1.1", "185.153.196.22", "192.168.0.1"],
            "Decisao": ["ALLOW", "DENY", "DROP", "ALLOW"],
            "Momento": ["2026-04-01 00:00:00", "2026-04-01 01:00:00", "2026-04-01 02:00:00", "2026-04-01 03:00:00"]
        })
        
        mapping, _ = auto_map_columns(df)
        
        # O detector tem que bater canonical -> real column
        self.assertEqual(mapping.get("destination_port"), "Batata")
        self.assertEqual(mapping.get("source_ip"), "Endereco")
        self.assertEqual(mapping.get("action"), "Decisao")
        self.assertEqual(mapping.get("timestamp"), "Momento")

if __name__ == "__main__":
    unittest.main()
