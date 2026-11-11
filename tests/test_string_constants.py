from types import SimpleNamespace
import unittest
from scanner.string_constants import reversed_name_evidence


def instruction(name, registers=(), reference=None):
    operands = [(0, n) for n in registers]
    if reference is not None:
        operands.append((256, 0, reference))
    return SimpleNamespace(get_name=lambda: name, get_operands=lambda: operands, get_length=lambda: 2)


def block_method(blocks):
    groups = [SimpleNamespace(get_start=lambda i=i: i*100,
                              get_instructions=lambda block=block: iter(block)) for i, block in enumerate(blocks)]
    return SimpleNamespace(get_basic_blocks=lambda: SimpleNamespace(gets=lambda: groups))


def sequence():
    return [instruction('const-string', [1], 'dIeciveDteg'),
            instruction('new-instance', [2], 'Ljava/lang/StringBuffer;'),
            instruction('invoke-direct', [2, 1], 'Ljava/lang/StringBuffer;-><init>(Ljava/lang/String;)V'),
            instruction('invoke-virtual', [2], 'Ljava/lang/StringBuffer;->reverse()Ljava/lang/StringBuffer;'),
            instruction('move-result-object', [2]),
            instruction('invoke-virtual', [2], 'Ljava/lang/StringBuffer;->toString()Ljava/lang/String;'),
            instruction('move-result-object', [3]),
            instruction('invoke-virtual', [4, 3, 5], 'Ljava/lang/Class;->getMethod(Ljava/lang/String; [Ljava/lang/Class;)Ljava/lang/reflect/Method;')]


class ReversedConstantTests(unittest.TestCase):
    def test_literal_reverse_and_reflective_use_have_offsets(self):
        proof = reversed_name_evidence(block_method([sequence()]))[0]
        self.assertEqual(proof['original'], 'dIeciveDteg')
        self.assertEqual(proof['decoded'], 'getDeviceId')
        self.assertEqual(proof['operations'][0]['offset'], 6)
        self.assertEqual(proof['use_offset'], 14)

    def test_no_propagation_across_blocks(self):
        instructions = sequence()
        self.assertFalse(reversed_name_evidence(block_method([instructions[:7], instructions[7:]])))

    def test_unknown_call_cannot_leave_mutable_builder_constant(self):
        instructions = sequence()
        instructions.insert(5, instruction('invoke-static', [], 'Lapp/Unknown;->mutate()V'))
        self.assertFalse(reversed_name_evidence(block_method([instructions])))

    def test_reversed_ui_text_without_reflective_use_is_not_reported(self):
        self.assertFalse(reversed_name_evidence(block_method([sequence()[:-1]])))

    def test_overwritten_register_does_not_reuse_decoded_constant(self):
        instructions = sequence()
        instructions.insert(7, instruction('const-string', [3], 'aDifferentName'))
        self.assertFalse(reversed_name_evidence(block_method([instructions])))


if __name__ == '__main__':
    unittest.main()
