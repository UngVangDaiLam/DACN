import unittest
from types import SimpleNamespace

from scanner.code_layers import analyze_code_layers, encoded_candidate, origin_for, MAX_FINDINGS


class Method:
    def __init__(self, cls, name, calls=(), descriptor="()V", external=False):
        self.cls, self.name, self.descriptor = cls, name, descriptor
        self.calls, self.external = calls, external

    def get_method(self):
        return self

    def get_class_name(self):
        return self.cls

    def get_name(self):
        return self.name

    def get_descriptor(self):
        return self.descriptor

    def is_external(self):
        return self.external

    def get_xref_to(self):
        return [(None, callee, offset) for offset, callee in enumerate(self.calls)]


def call(cls, name):
    return Method(cls, name, external=True)


SOURCE = call("Landroid/location/Location;", "getLatitude")
SINK = call("Ljava/net/HttpURLConnection;", "getOutputStream")
DEX = call("Ldalvik/system/DexClassLoader;", "<init>")


def analyze(methods, strings=()):
    apk = SimpleNamespace(get_package=lambda: "org.example")
    analysis = SimpleNamespace(get_methods=lambda: iter(methods), get_strings=lambda: iter(strings))
    return analyze_code_layers(apk, analysis, {})


class CodeLayerTests(unittest.TestCase):
    def test_dynamic_loading_reports_caller_and_offset(self):
        report = analyze([Method("Lorg/example/Main;", "load", [DEX])])
        hit = report["layer2"]["findings"][0]
        self.assertEqual(hit["class_name"], "Lorg/example/Main;")
        self.assertEqual(hit["method_name"], "load")
        self.assertEqual(hit["calls"][0]["offset"], 0)
        self.assertEqual(hit["origin"], "application")

    def test_same_method_is_a_candidate_not_confirmed_flow(self):
        report = analyze([Method("Lorg/example/Main;", "send", [SOURCE, SINK])])
        hit = report["layer3"]["findings"][0]
        self.assertFalse(hit["flow_confirmed"])
        self.assertEqual(hit["data_types"], ["Vị trí"])
        self.assertEqual(hit["evidence_family"], "code_behavior")

    def test_separate_methods_do_not_match(self):
        report = analyze([Method("Lorg/example/Main;", "read", [SOURCE]),
                          Method("Lorg/example/Main;", "send", [SINK])])
        self.assertEqual(report["layer3"]["finding_count"], 0)

    def test_overloaded_methods_are_not_merged(self):
        report = analyze([Method("Lorg/example/Main;", "run", [SOURCE], "()V"),
                          Method("Lorg/example/Main;", "run", [SINK], "(I)V")])
        self.assertEqual(report["layer3"]["finding_count"], 0)

    def test_network_only_and_external_methods_do_not_match(self):
        report = analyze([Method("Lorg/example/Main;", "send", [SINK]),
                          Method("Lorg/example/Main;", "external", [SOURCE, SINK], external=True)])
        self.assertEqual(report["layer3"]["finding_count"], 0)
        self.assertEqual(report["layer3"]["methods_scanned"], 1)

    def test_sms_sending_is_not_treated_as_sms_reading(self):
        sms = call("Landroid/telephony/SmsManager;", "sendTextMessage")
        report = analyze([Method("Lorg/example/Main;", "run", [sms, SINK])])
        self.assertEqual(report["layer3"]["finding_count"], 0)

    def test_library_is_retained_with_lower_severity(self):
        report = analyze([Method("Lcom/google/sdk/Tracker;", "send", [SOURCE, SINK])])
        hit = report["layer3"]["findings"][0]
        self.assertEqual(hit["origin"], "third_party")
        self.assertEqual(hit["severity"], "low")
        self.assertEqual(origin_for("La/b;", "org.example"), "unknown")
        self.assertEqual(origin_for("Lorg/exampleevil/Main;", "org.example"), "unknown")

    def test_encoded_string_has_location(self):
        value = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 2
        method = Method("Lorg/example/Main;", "decode")
        string = SimpleNamespace(get_value=lambda: value,
                                 get_xref_from=lambda with_offset: [(None, method, 24)])
        report = analyze([method], [string])
        self.assertEqual(report["layer2"]["findings"][0]["strings"][0]["offset"], 24)
        self.assertFalse(encoded_candidate("a" * 100))
        self.assertFalse(encoded_candidate("https://example.com/" * 10))

    def test_evidence_limit_preserves_total_counts(self):
        report = analyze([Method("Lorg/example/Main;", f"run{i}", [SOURCE, SINK])
                          for i in range(MAX_FINDINGS + 5)])
        layer = report["layer3"]
        self.assertEqual(layer["finding_count"], MAX_FINDINGS + 5)
        self.assertEqual(len(layer["findings"]), MAX_FINDINGS)
        self.assertTrue(layer["truncated"])

    def test_broken_method_is_partial_and_does_not_hide_later_findings(self):
        broken = Method("Lorg/example/Main;", "broken")
        broken.get_xref_to = lambda: (_ for _ in ()).throw(ValueError("bad dex"))
        report = analyze([broken, Method("Lorg/example/Main;", "load", [DEX])])
        self.assertEqual(report["layer2"]["status"], "partial")
        self.assertEqual(report["layer2"]["analysis_errors"], 1)
        self.assertEqual(report["layer2"]["finding_count"], 1)

    def test_application_evidence_is_kept_when_libraries_fill_report(self):
        methods = [Method("Lcom/google/sdk/Tracker;", f"run{i}", [SOURCE, SINK])
                   for i in range(MAX_FINDINGS)]
        methods.append(Method("Lorg/example/Main;", "send", [SOURCE, SINK]))
        layer = analyze(methods)["layer3"]
        self.assertEqual(layer["finding_count"], MAX_FINDINGS + 1)
        self.assertEqual(layer["findings"][0]["origin"], "application")


if __name__ == "__main__":
    unittest.main()
