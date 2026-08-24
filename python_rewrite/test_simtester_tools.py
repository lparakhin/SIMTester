import unittest

from python_rewrite.simtester_tools import (
    build_command_packet,
    build_sms_pp_download_apdu,
    decode_apdu_response,
)


class OTAPacketTests(unittest.TestCase):
    def test_command_packet_contains_requested_tar_and_keyset(self):
        packet = build_command_packet(bytes.fromhex("B00001"), 3)

        self.assertEqual(packet[:3], bytes.fromhex("027000"))
        self.assertEqual(int.from_bytes(packet[3:5], "big"), len(packet) - 5)
        self.assertEqual(packet[5], 13)
        self.assertEqual(packet[6:10], bytes.fromhex("00293030"))
        self.assertEqual(packet[10:13], bytes.fromhex("B00001"))
        self.assertTrue(packet.endswith(bytes.fromhex("A0A40000023F00")))

    def test_sms_pp_download_is_uicc_envelope_not_select_mf(self):
        packet = build_command_packet(bytes.fromhex("000000"), 0)
        apdu = build_sms_pp_download_apdu(packet)

        self.assertEqual(apdu[:4], bytes.fromhex("80C20000"))
        self.assertEqual(apdu[4], len(apdu) - 5)
        self.assertIn(packet, apdu)
        self.assertNotEqual(apdu, bytes.fromhex("00A40000023F00"))

    def test_6f00_has_standards_appropriate_diagnosis(self):
        self.assertEqual(
            decode_apdu_response(bytes.fromhex("6F00")),
            "Technical problem; no precise diagnosis available",
        )


if __name__ == "__main__":
    unittest.main()
